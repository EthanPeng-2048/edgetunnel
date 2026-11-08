/**
 * UUID 文本 ↔ 16 字节（原 _worker.js getUuidBytes/uuidBytesMatch，VLESS 与 WS early data 共用）。
 * 带 LRU 上限缓存（原 uuidBytesCache，上限 32 条）。
 */
const uuidBytesCache = new Map<string, Uint8Array | null>();

function readHexNibble(code: number): number {
  if (code >= 48 && code <= 57) return code - 48;
  code |= 32;
  if (code >= 97 && code <= 102) return code - 87;
  return -1;
}

export function getUuidBytes(uuid: string): Uint8Array | null {
  const key = String(uuid || '');
  const cached = uuidBytesCache.get(key);
  if (cached !== undefined) return cached;

  const clean = key.replace(/-/g, '');
  if (clean.length !== 32) {
    uuidBytesCache.set(key, null);
    return null;
  }

  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    const high = readHexNibble(clean.charCodeAt(i * 2));
    const low = readHexNibble(clean.charCodeAt(i * 2 + 1));
    if (high < 0 || low < 0) {
      uuidBytesCache.set(key, null);
      return null;
    }
    bytes[i] = (high << 4) | low;
  }

  if (uuidBytesCache.size >= 32) uuidBytesCache.clear();
  uuidBytesCache.set(key, bytes);
  return bytes;
}

/** data[offset..offset+16) 是否等于 uuid 的 16 字节 */
export function uuidBytesMatch(data: Uint8Array, offset: number, uuid: string): boolean {
  const expected = getUuidBytes(uuid);
  if (!expected || data.byteLength < offset + 16) return false;
  for (let i = 0; i < 16; i++) {
    if (data[offset + i] !== expected[i]) return false;
  }
  return true;
}
