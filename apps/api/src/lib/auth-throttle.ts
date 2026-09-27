import type { AuthAuditAction, Prisma } from '@prisma/client';
import type { FastifyRequest } from 'fastify';
import { env } from '../config/env.js';
import { prisma } from './prisma.js';
import { AppError } from './errors.js';
import { normalizeEmail } from './identity.js';

// 失败额度键与认证判定使用同一个 normalizeEmail，格式变形无法产生新键。
export function loginSubjectKey(email: string): string {
  return `login:${normalizeEmail(email)}`;
}

export function userSubjectKey(userId: string): string {
  return `user:${userId}`;
}

export interface ThrottleConfig {
  maxFailures: number;
  windowMs: number;
  lockMs: number;
}

export function authThrottleConfig(): ThrottleConfig {
  return {
    maxFailures: env.AUTH_FAILURE_MAX,
    windowMs: env.AUTH_FAILURE_WINDOW_MINUTES * 60 * 1000,
    lockMs: env.AUTH_LOCK_MINUTES * 60 * 1000
  };
}

export interface ThrottleState {
  failures: number;
  windowStartAt: Date;
  lockedUntil: Date | null;
}

export function activeLockUntil(state: Pick<ThrottleState, 'lockedUntil'>, now: Date): Date | null {
  return state.lockedUntil && state.lockedUntil.getTime() > now.getTime() ? state.lockedUntil : null;
}

export type FailureVerdict =
  | { kind: 'failed'; failures: number }
  | { kind: 'locked'; lockedUntil: Date };

// 纯状态机：给定行锁保护下的当前状态与权威时间，计算一次失败后的下一状态。
// 锁定期内的失败不再累加计数；窗口过期后重新计数；达到阈值即锁定并清零。
export function applyFailure(
  state: ThrottleState,
  now: Date,
  config: ThrottleConfig
): { next: ThrottleState; verdict: FailureVerdict } {
  const existingLock = activeLockUntil(state, now);
  if (existingLock) {
    return { next: state, verdict: { kind: 'locked', lockedUntil: existingLock } };
  }
  const windowExpired = now.getTime() - state.windowStartAt.getTime() >= config.windowMs;
  const failures = windowExpired ? 1 : state.failures + 1;
  if (failures >= config.maxFailures) {
    const lockedUntil = new Date(now.getTime() + config.lockMs);
    return {
      next: { failures: 0, windowStartAt: now, lockedUntil },
      verdict: { kind: 'locked', lockedUntil }
    };
  }
  return {
    next: {
      failures,
      windowStartAt: windowExpired ? now : state.windowStartAt,
      lockedUntil: null
    },
    verdict: { kind: 'failed', failures }
  };
}

export interface AuditContext {
  userId?: string | null;
  ip?: string | null;
  userAgent?: string | null;
}

export function auditContext(request: FastifyRequest, userId?: string | null): AuditContext {
  const userAgent = request.headers['user-agent'];
  return {
    userId: userId ?? null,
    ip: request.ip,
    userAgent: userAgent ? userAgent.slice(0, 300) : null
  };
}

type Tx = Prisma.TransactionClient;

interface LockedRow extends ThrottleState {
  now: Date;
}

// 插入（不存在时）并 SELECT ... FOR UPDATE：并发事务在行锁上串行，
// 所有节点读写同一行，计数与锁定不会分叉。时间一律取数据库 NOW()，避免节点时钟漂移。
async function lockRowForUpdate(tx: Tx, subjectKey: string): Promise<LockedRow> {
  await tx.$executeRaw`
    INSERT INTO "auth_throttles" ("id", "subject_key", "window_start_at", "created_at", "updated_at")
    VALUES (gen_random_uuid(), ${subjectKey}, NOW(), NOW(), NOW())
    ON CONFLICT ("subject_key") DO NOTHING`;
  const rows = await tx.$queryRaw<
    Array<{ failures: number; windowStartAt: Date; lockedUntil: Date | null; now: Date }>
  >`
    SELECT "failures",
           "window_start_at" AS "windowStartAt",
           "locked_until"    AS "lockedUntil",
           NOW()             AS "now"
    FROM "auth_throttles"
    WHERE "subject_key" = ${subjectKey}
    FOR UPDATE`;
  const row = rows[0];
  if (!row) throw new Error(`auth_throttles row missing for ${subjectKey}`);
  return row;
}

async function writeAudit(tx: Tx, subjectKey: string, action: AuthAuditAction, ctx: AuditContext): Promise<void> {
  await tx.authAuditEvent.create({
    data: {
      subjectKey,
      action,
      userId: ctx.userId ?? null,
      ip: ctx.ip ?? null,
      userAgent: ctx.userAgent ?? null
    }
  });
}

function lockedMessage(until: Date, now: Date): string {
  const minutes = Math.max(1, Math.ceil((until.getTime() - now.getTime()) / (60 * 1000)));
  return `失败次数过多，已临时锁定，请约 ${minutes} 分钟后再试`;
}

// 快速闸门：已锁定的主题直接拒绝并写审计。真正的并发防线在 recordAuthFailure 的行锁里。
export async function assertAuthNotLocked(
  subjectKey: string,
  lockedAction: AuthAuditAction,
  ctx: AuditContext
): Promise<void> {
  const locked = await prisma.$transaction(async (tx) => {
    const rows = await tx.$queryRaw<Array<{ lockedUntil: Date | null; now: Date }>>`
      SELECT "locked_until" AS "lockedUntil", NOW() AS "now"
      FROM "auth_throttles"
      WHERE "subject_key" = ${subjectKey}`;
    const row = rows[0];
    const until = row ? activeLockUntil({ lockedUntil: row.lockedUntil }, row.now) : null;
    if (!row || !until) return null;
    await writeAudit(tx, subjectKey, lockedAction, ctx);
    return { until, now: row.now };
  });
  if (locked) {
    throw new AppError(429, 'AUTH_LOCKED', lockedMessage(locked.until, locked.now));
  }
}

// 记录一次失败。状态变更与审计在同一事务提交；若本次失败触发锁定（或已处于锁定），
// 事务提交后抛出 429，否则由调用方返回原本的失败响应。
export async function recordAuthFailure(
  subjectKey: string,
  actions: { failed: AuthAuditAction; locked: AuthAuditAction },
  ctx: AuditContext,
  config: ThrottleConfig = authThrottleConfig()
): Promise<void> {
  const result = await prisma.$transaction(async (tx) => {
    const state = await lockRowForUpdate(tx, subjectKey);
    const { next, verdict } = applyFailure(state, state.now, config);
    await tx.authThrottle.update({
      where: { subjectKey },
      data: {
        failures: next.failures,
        windowStartAt: next.windowStartAt,
        lockedUntil: next.lockedUntil
      }
    });
    await writeAudit(tx, subjectKey, verdict.kind === 'locked' ? actions.locked : actions.failed, ctx);
    return { verdict, now: state.now };
  });
  if (result.verdict.kind === 'locked') {
    throw new AppError(429, 'AUTH_LOCKED', lockedMessage(result.verdict.lockedUntil, result.now));
  }
}

// 成功后清零计数并写审计。不为首次成功创建额度行；已生效的锁定不被成功清除。
export async function recordAuthSuccess(
  subjectKey: string,
  action: AuthAuditAction,
  ctx: AuditContext
): Promise<void> {
  await prisma.$transaction(async (tx) => {
    const rows = await tx.$queryRaw<
      Array<{ failures: number; windowStartAt: Date; lockedUntil: Date | null; now: Date }>
    >`
      SELECT "failures",
             "window_start_at" AS "windowStartAt",
             "locked_until"    AS "lockedUntil",
             NOW()             AS "now"
      FROM "auth_throttles"
      WHERE "subject_key" = ${subjectKey}
      FOR UPDATE`;
    const row = rows[0];
    if (row && !activeLockUntil(row, row.now)) {
      await tx.authThrottle.update({
        where: { subjectKey },
        data: { failures: 0, windowStartAt: row.now, lockedUntil: null }
      });
    }
    await writeAudit(tx, subjectKey, action, ctx);
  });
}
