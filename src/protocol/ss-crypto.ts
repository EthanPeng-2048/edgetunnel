/**
 * Shadowsocks AEAD 加密原语（原 _worker.js SS_CIPHER_CONFIGS / ssDerive* / ssAead*，行为等价移植）。
 *
 * 与原实现的唯一差异：主密钥派生的 MD5 链用 services/md5 的纯 TS md5Bytes
 * （原为 CF 专有 crypto.subtle.digest('MD5')，Node/Vitest 不支持）。
 * 会话密钥 HMAC-SHA1 与 AES-GCM 走标准 WebCrypto，双环境可用。
 */
import { md5Bytes } from '../services/md5';
import { concatByteChunks } from '../utils/bytes';

export interface SsCipherConfig {
  method: string;
  keyLen: number;
  saltLen: number;
  maxChunk: number;
  aesLength: 128 | 256;
}

export const SS_CIPHER_CONFIGS: Record<string, SsCipherConfig> = {
  'aes-128-gcm': { method: 'aes-128-gcm', keyLen: 16, saltLen: 16, maxChunk: 0x3fff, aesLength: 128 },
  'aes-256-gcm': { method: 'aes-256-gcm', keyLen: 32, saltLen: 32, maxChunk: 0x3fff, aesLength: 256 },
};

export const SS_AEAD_TAG_LEN = 16;
export const SS_NONCE_LEN = 12;
const SS_SUBKEY_INFO = new TextEncoder().encode('ss-subkey');

/** 线性计数器 +1（little-endian，进位到字节为 0 时继续）—— 原 ssIncrementNonce */
export function ssIncrementNonce(counter: Uint8Array): void {
  for (let i = 0; i < counter.length; i++) {
    counter[i] = (counter[i]! + 1) & 0xff;
    if (counter[i] !== 0) return;
  }
}

/** 主密钥：password 的 MD5 迭代链（EVP_BytesToKey 变体）—— 原 ssDeriveMasterKey */
const ssMasterKeyCache = new Map<string, Uint8Array>();

export function ssDeriveMasterKey(passwordText: string, keyLen: number): Uint8Array {
  const cacheKey = `${keyLen}:${passwordText}`;
  const cached = ssMasterKeyCache.get(cacheKey);
  if (cached) return cached;

  const pwBytes = new TextEncoder().encode(passwordText || '');
  let prev: Uint8Array = new Uint8Array(0);
  let result: Uint8Array = new Uint8Array(0);
  while (result.byteLength < keyLen) {
    const input = concatByteChunks(prev, pwBytes);
    prev = md5Bytes(input);
    result = concatByteChunks(result, prev);
  }
  const key = result.slice(0, keyLen);
  ssMasterKeyCache.set(cacheKey, key);
  return key;
}

/**
 * 会话子密钥：HMAC-SHA1(salt, masterKey) 为 PRK，再按 "ss-subkey" info 扩展。
 * —— 原 ssDeriveSessionKey（WebCrypto HMAC + AES-GCM importKey）
 */
export async function ssDeriveSessionKey(
  config: SsCipherConfig,
  masterKey: Uint8Array,
  salt: Uint8Array,
  usages: Array<'encrypt' | 'decrypt'>,
): Promise<CryptoKey> {
  const hmacOpts = { name: 'HMAC', hash: 'SHA-1' } as const;
  const saltHmacKey = await crypto.subtle.importKey('raw', salt, hmacOpts, false, ['sign']);
  const prk = new Uint8Array(await crypto.subtle.sign('HMAC', saltHmacKey, masterKey));
  const prkHmacKey = await crypto.subtle.importKey('raw', prk, hmacOpts, false, ['sign']);
  const subKey = new Uint8Array(config.keyLen);
  let prev = new Uint8Array(0);
  let written = 0;
  let counter = 1;
  while (written < config.keyLen) {
    const input = concatByteChunks(prev, SS_SUBKEY_INFO, new Uint8Array([counter]));
    prev = new Uint8Array(await crypto.subtle.sign('HMAC', prkHmacKey, input));
    const copyLen = Math.min(prev.byteLength, config.keyLen - written);
    subKey.set(prev.subarray(0, copyLen), written);
    written += copyLen;
    counter += 1;
  }
  return crypto.subtle.importKey('raw', subKey, { name: 'AES-GCM', length: config.aesLength }, false, usages);
}

/** AEAD 加密（nonce 计数器就地 +1）—— 原 ssAeadEncrypt */
export async function ssAeadEncrypt(cryptoKey: CryptoKey, nonceCounter: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const iv = nonceCounter.slice();
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, cryptoKey, plaintext);
  ssIncrementNonce(nonceCounter);
  return new Uint8Array(ct);
}

/** AEAD 解密（nonce 计数器就地 +1；失败抛 OperationError）—— 原 ssAeadDecrypt */
export async function ssAeadDecrypt(cryptoKey: CryptoKey, nonceCounter: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  const iv = nonceCounter.slice();
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, cryptoKey, ciphertext);
  ssIncrementNonce(nonceCounter);
  return new Uint8Array(pt);
}

/** 按 URL ?enc= 选偏好套件（未知值回退 aes-128-gcm），候选序 = [偏好, ...其余] —— 原 getSsContext 逻辑 */
export function ssCandidateConfigs(encMethod: string | null | undefined): SsCipherConfig[] {
  const preferred = SS_CIPHER_CONFIGS[(encMethod || '').toLowerCase()] || SS_CIPHER_CONFIGS['aes-128-gcm']!;
  return [preferred, ...Object.values(SS_CIPHER_CONFIGS).filter((c) => c.method !== preferred.method)];
}
