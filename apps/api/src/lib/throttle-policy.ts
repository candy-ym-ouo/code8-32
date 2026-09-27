/**
 * 认证失败额度的纯判定逻辑,与存储层分离以便单测。
 */

/**
 * 一次认证尝试是否应被拒绝。
 *
 * failCount 为原子计数语句返回的、本次尝试计入后的次数:
 * 第 maxFailures 次尝试仍被放行(用掉最后一次额度),超过即拒绝;
 * 锁定未过期一律拒绝。
 */
export function isAttemptBlocked(
  failCount: number,
  lockedUntil: Date | null,
  maxFailures: number,
  now: Date = new Date()
): boolean {
  if (lockedUntil && lockedUntil.getTime() > now.getTime()) return true;
  return failCount > maxFailures;
}

/** 将分钟数转为 PostgreSQL interval 字面量,供 CAST($x AS interval) 使用。 */
export function minutesInterval(minutes: number): string {
  return `${Math.trunc(minutes)} minutes`;
}
