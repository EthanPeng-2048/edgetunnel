/** 敏感字段掩码（原 maskSensitive）：保留首 3 尾 2 位，中间以 * 填充。 */
export function maskSensitive(text: string | null, prefixLen = 3, suffixLen = 2): string | null {
  if (!text) return text;
  if (text.length <= prefixLen + suffixLen) return text;
  const prefix = text.slice(0, prefixLen);
  const suffix = text.slice(-suffixLen);
  const starCount = text.length - prefixLen - suffixLen;
  return `${prefix}${'*'.repeat(starCount)}${suffix}`;
}
