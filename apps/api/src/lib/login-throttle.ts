import { Prisma, type AuthAuditAction } from '@prisma/client';
import { env } from '../config/env.js';
import { prisma } from './prisma.js';
import { AppError } from './errors.js';
import { normalizeEmail } from './email.js';
import { isAttemptBlocked, minutesInterval } from './throttle-policy.js';

/**
 * 跨节点一致的认证失败额度与锁定。
 *
 * 状态保存在 PostgreSQL(login_throttles 表),所有 API 节点共享同一份计数与锁定;
 * 计数通过单条 INSERT ... ON CONFLICT 语句原子完成,并发请求由行锁串行化,
 * 因此格式变形、实例切换和并发尝试都无法绕过失败额度。
 * 锁定状态变更与审计事件(auth_audit_events 表)在同一事务中提交。
 */

interface AttemptRow {
  failCount: number;
  lockedUntil: Date | null;
}

interface AuditInput {
  email: string;
  userId?: string | null;
  ip?: string | null;
}

function lockedError(): AppError {
  return new AppError(429, 'AUTH_LOCKED', '失败次数过多，账号已临时锁定，请稍后重试');
}

/**
 * 原子占用一次认证尝试额度,必须在校验密码之前调用。
 * 额度已用尽或锁定未过期时抛出 429,本次请求不再执行密码校验。
 */
export async function beginAuthAttempt(rawEmail: string): Promise<void> {
  const email = normalizeEmail(rawEmail);
  const rows = await prisma.$queryRaw<AttemptRow[]>`
    INSERT INTO login_throttles (email, fail_count, window_start, locked_until, updated_at)
    VALUES (${email}, 1, now(), NULL, now())
    ON CONFLICT (email) DO UPDATE SET
      fail_count = CASE
        WHEN login_throttles.locked_until IS NOT NULL AND login_throttles.locked_until <= now() THEN 1
        WHEN login_throttles.window_start < now() - CAST(${minutesInterval(env.LOGIN_WINDOW_MINUTES)} AS interval) THEN 1
        ELSE login_throttles.fail_count + 1
      END,
      window_start = CASE
        WHEN login_throttles.locked_until IS NOT NULL AND login_throttles.locked_until <= now() THEN now()
        WHEN login_throttles.window_start < now() - CAST(${minutesInterval(env.LOGIN_WINDOW_MINUTES)} AS interval) THEN now()
        ELSE login_throttles.window_start
      END,
      locked_until = CASE
        WHEN login_throttles.locked_until IS NOT NULL AND login_throttles.locked_until <= now() THEN NULL
        ELSE login_throttles.locked_until
      END,
      updated_at = now()
    RETURNING fail_count AS "failCount", locked_until AS "lockedUntil"
  `;
  const row = rows[0];
  if (!row || isAttemptBlocked(row.failCount, row.lockedUntil, env.LOGIN_MAX_FAILURES)) {
    throw lockedError();
  }
}

/**
 * 记录一次失败的认证尝试:达到额度即锁定账号,
 * 锁定与审计事件在同一事务提交,任何节点看到的都一致。
 */
export async function recordAuthFailure(
  input: AuditInput & { action: 'LOGIN_FAILED' | 'PASSWORD_VERIFY_FAILED' }
): Promise<void> {
  const email = normalizeEmail(input.email);
  await prisma.$transaction(async (tx) => {
    const newlyLocked = await tx.$executeRaw`
      UPDATE login_throttles
      SET locked_until = now() + CAST(${minutesInterval(env.LOGIN_LOCK_MINUTES)} AS interval),
          updated_at = now()
      WHERE email = ${email}
        AND fail_count >= ${env.LOGIN_MAX_FAILURES}
        AND (locked_until IS NULL OR locked_until <= now())
    `;
    await writeAudit(tx, input, email, input.action);
    if (newlyLocked > 0) {
      await writeAudit(tx, input, email, 'LOGIN_LOCKED');
    }
  });
}

/**
 * 记录一次成功的认证:清零失败计数并写审计。
 * 若账号刚被并发请求锁定,保留锁定(删除条件不满足),由后续尝试在锁过期后重置。
 */
export async function recordAuthSuccess(
  input: AuditInput & { userId: string; action: 'LOGIN_SUCCEEDED' | 'PASSWORD_CHANGED' }
): Promise<void> {
  const email = normalizeEmail(input.email);
  await prisma.$transaction(async (tx) => {
    await tx.$executeRaw`
      DELETE FROM login_throttles
      WHERE email = ${email}
        AND (locked_until IS NULL OR locked_until <= now())
    `;
    await writeAudit(tx, input, email, input.action);
  });
}

type Tx = Prisma.TransactionClient;

async function writeAudit(
  tx: Tx,
  input: AuditInput,
  email: string,
  action: AuthAuditAction
): Promise<void> {
  await tx.authAuditEvent.create({
    data: {
      email,
      userId: input.userId ?? null,
      ip: input.ip ?? null,
      action
    }
  });
}
