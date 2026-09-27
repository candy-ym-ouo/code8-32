/**
 * 账号邮箱的唯一归一化入口。
 *
 * 账号查找、失败额度计数、锁定与审计必须使用同一个归一化结果,
 * 否则 "User@x.com"、" user@x.com "、Unicode 分解形式(NFD)等格式变体
 * 会落入不同的计数桶,却能解析到同一个账号,从而绕过失败额度。
 */
export function normalizeEmail(email: string): string {
  return email.normalize('NFC').trim().toLowerCase();
}
