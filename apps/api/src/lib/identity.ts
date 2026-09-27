// 账号标识的唯一规范化入口。认证查询、失败额度键、审计记录必须使用同一结果，
// 否则大小写、首尾空白或 Unicode 形态（NFC/NFD）差异会产生多个额度键。
export function normalizeEmail(email: string): string {
  return email.normalize('NFC').trim().toLowerCase();
}
