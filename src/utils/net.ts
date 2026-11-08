/**
 * 网络主机名工具（原 _worker.js stripIPv6Brackets / isIPHostname / isIPv4）。
 */

/** 去掉 IPv6 方括号（原 stripIPv6Brackets） */
export function stripIPv6Brackets(hostname = ''): string {
  const host = String(hostname || '').trim();
  return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

/** 是否 IPv4 点分十进制（原 isIPv4） */
export function isIPv4(value: unknown): boolean {
  const parts = String(value || '').split('.');
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

/** 是否 IP 字面量（IPv4 或 IPv6，原 isIPHostname） */
export function isIPHostname(hostname = ''): boolean {
  const host = stripIPv6Brackets(hostname);
  const ipv4Regex = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
  if (ipv4Regex.test(host)) return true;
  if (!host.includes(':')) return false;
  try {
    void new URL(`http://[${host}]/`);
    return true;
  } catch {
    return false;
  }
}
