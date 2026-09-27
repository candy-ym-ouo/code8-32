import type { FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { prisma } from '../../lib/prisma.js';
import { AppError, zodFields } from '../../lib/errors.js';
import {
  createSession,
  currentUser,
  deleteCurrentSession,
  hashPassword,
  requireAuth,
  verifyPassword
} from '../../lib/auth.js';
import { normalizeEmail } from '../../lib/identity.js';
import {
  assertAuthNotLocked,
  auditContext,
  loginSubjectKey,
  recordAuthFailure,
  recordAuthSuccess,
  userSubjectKey
} from '../../lib/auth-throttle.js';

const credentialsSchema = z.object({
  email: z.string().trim().email('请输入有效邮箱').max(320),
  password: z.string().min(8, '密码至少 8 位').max(128)
});

const passwordChangeSchema = z.object({
  currentPassword: z.string().min(1),
  newPassword: z.string().min(8, '新密码至少 8 位').max(128)
});

const deleteAccountSchema = z.object({
  password: z.string().min(1, '请输入密码')
});

function publicUser(user: { id: string; email: string; createdAt: Date }) {
  return { id: user.id, email: user.email, createdAt: user.createdAt };
}

export const authRoutes: FastifyPluginAsync = async (app) => {
  app.post(
    '/register',
    {
      config: {
        rateLimit: {
          max: 5,
          timeWindow: '1 hour'
        }
      }
    },
    async (request, reply) => {
      const parsed = credentialsSchema.safeParse(request.body);
      if (!parsed.success) {
        throw new AppError(422, 'VALIDATION_ERROR', '注册信息无效', zodFields(parsed.error));
      }
      const email = normalizeEmail(parsed.data.email);
      const existing = await prisma.user.findUnique({ where: { email } });
      if (existing) throw new AppError(409, 'EMAIL_EXISTS', '该邮箱已注册');

      const user = await prisma.user.create({
        data: { email, passwordHash: await hashPassword(parsed.data.password) }
      });
      await createSession(user.id, reply);
      return reply.status(201).send({ user: publicUser(user) });
    }
  );

  app.post(
    '/login',
    {
      // 仅作每实例的 IP 级粗限流；账户级失败额度由数据库中的 auth_throttles 保证，
      // 不依赖本插件的内存计数（多节点部署下各实例计数互不可见）。
      config: {
        rateLimit: {
          max: 10,
          timeWindow: '15 minutes'
        }
      }
    },
    async (request, reply) => {
      const parsed = credentialsSchema.safeParse(request.body);
      if (!parsed.success) {
        throw new AppError(401, 'INVALID_CREDENTIALS', '邮箱或密码错误');
      }
      const email = normalizeEmail(parsed.data.email);
      const subjectKey = loginSubjectKey(email);
      await assertAuthNotLocked(subjectKey, 'LOGIN_LOCKED', auditContext(request));

      const user = await prisma.user.findUnique({ where: { email } });
      const valid = user ? await verifyPassword(user.passwordHash, parsed.data.password) : false;
      if (!user || !valid || user.status !== 'ACTIVE' || user.deletedAt) {
        await recordAuthFailure(
          subjectKey,
          { failed: 'LOGIN_FAILED', locked: 'LOGIN_LOCKED' },
          auditContext(request, user?.id)
        );
        throw new AppError(401, 'INVALID_CREDENTIALS', '邮箱或密码错误');
      }
      await recordAuthSuccess(subjectKey, 'LOGIN_SUCCESS', auditContext(request, user.id));
      await createSession(user.id, reply);
      return { user: publicUser(user) };
    }
  );

  app.post('/logout', { preHandler: requireAuth }, async (request, reply) => {
    await deleteCurrentSession(request, reply);
    return reply.status(204).send();
  });

  app.get('/me', { preHandler: requireAuth }, async (request) => {
    return { user: currentUser(request) };
  });

  app.patch('/password', { preHandler: requireAuth }, async (request, reply) => {
    const parsed = passwordChangeSchema.safeParse(request.body);
    if (!parsed.success) {
      throw new AppError(422, 'VALIDATION_ERROR', '密码信息无效', zodFields(parsed.error));
    }
    const authUser = currentUser(request);
    // 已登录会话校验密码同样计入失败额度，旧会话不能无限重试。
    const subjectKey = userSubjectKey(authUser.id);
    await assertAuthNotLocked(subjectKey, 'PASSWORD_VERIFY_LOCKED', auditContext(request, authUser.id));

    const user = await prisma.user.findUniqueOrThrow({ where: { id: authUser.id } });
    const valid = await verifyPassword(user.passwordHash, parsed.data.currentPassword);
    if (!valid) {
      await recordAuthFailure(
        subjectKey,
        { failed: 'PASSWORD_VERIFY_FAILED', locked: 'PASSWORD_VERIFY_LOCKED' },
        auditContext(request, authUser.id)
      );
      throw new AppError(422, 'INVALID_PASSWORD', '当前密码不正确');
    }
    await recordAuthSuccess(subjectKey, 'PASSWORD_VERIFY_SUCCESS', auditContext(request, authUser.id));

    await prisma.user.update({
      where: { id: authUser.id },
      data: { passwordHash: await hashPassword(parsed.data.newPassword) }
    });
    await createSession(authUser.id, reply, true);
    return { ok: true };
  });

  app.delete('/account', { preHandler: requireAuth }, async (request, reply) => {
    const parsed = deleteAccountSchema.safeParse(request.body);
    if (!parsed.success) {
      throw new AppError(422, 'VALIDATION_ERROR', '请输入密码', zodFields(parsed.error));
    }
    const authUser = currentUser(request);
    const subjectKey = userSubjectKey(authUser.id);
    await assertAuthNotLocked(subjectKey, 'PASSWORD_VERIFY_LOCKED', auditContext(request, authUser.id));

    const user = await prisma.user.findUniqueOrThrow({ where: { id: authUser.id } });
    if (!(await verifyPassword(user.passwordHash, parsed.data.password))) {
      await recordAuthFailure(
        subjectKey,
        { failed: 'PASSWORD_VERIFY_FAILED', locked: 'PASSWORD_VERIFY_LOCKED' },
        auditContext(request, authUser.id)
      );
      throw new AppError(422, 'INVALID_PASSWORD', '密码不正确');
    }
    await recordAuthSuccess(subjectKey, 'PASSWORD_VERIFY_SUCCESS', auditContext(request, authUser.id));

    const now = new Date();
    await prisma.$transaction([
      prisma.session.updateMany({
        where: { userId: authUser.id, revokedAt: null },
        data: { revokedAt: now }
      }),
      prisma.user.update({
        where: { id: authUser.id },
        data: { status: 'DELETED', deletedAt: now }
      })
    ]);
    reply.clearCookie('pbt_session', { path: '/' });
    return reply.status(204).send();
  });
};
