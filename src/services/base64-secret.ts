/**
 * 带秘钥的 Base64 编解码（原 _worker.js base64SecretEncode / base64SecretDecode，L4783-4824）。
 *
 * 用于两处兼容契约（勿改算法）：
 * 1. 订阅后端 token 种子：base64SecretEncode(MD5MD5(host+uuid), uuid) 再做 MD5MD5 日切；
 * 2. 订阅生成的 /video/<b64> 链式代理路径 —— 编码 JSON { type, hostname, port, ... }，
 *    proxy-ctx 用同一秘钥（userID/UUID）解码还原链式参数。
 */
const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** 秘钥 XOR 明文后转标准 Base64（原 base64SecretEncode） */
export function base64SecretEncode(plaintext: string, secret: string): string {
  const data = encoder.encode(plaintext);
  const key = encoder.encode(secret);
  const mixed = new Uint8Array(data.length);

  for (let i = 0; i < data.length; i++) {
    mixed[i] = data[i]! ^ key[i % key.length]!;
  }

  // 将 Uint8Array 转换为可被 btoa 处理的字符串
  let binary = '';
  for (let i = 0; i < mixed.length; i++) {
    binary += String.fromCharCode(mixed[i]!);
  }
  return btoa(binary);
}

/** Base64 解出 XOR 密文再异或秘钥还原明文（原 base64SecretDecode） */
export function base64SecretDecode(encoded: string, secret: string): string {
  const binary = atob(encoded);
  const mixed = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    mixed[i] = binary.charCodeAt(i);
  }

  const key = encoder.encode(secret);
  const data = new Uint8Array(mixed.length);

  for (let i = 0; i < mixed.length; i++) {
    data[i] = mixed[i]! ^ key[i % key.length]!;
  }

  return decoder.decode(data);
}
