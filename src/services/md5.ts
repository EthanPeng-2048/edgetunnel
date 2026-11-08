/**
 * MD5 与 MD5MD5 双哈希（原 _worker.js MD5MD5，行为等价移植）。
 *
 * 原实现依赖 `crypto.subtle.digest('MD5', ...)` —— Cloudflare Workers 的
 * WebCrypto 扩展，Node/Vitest 不支持。这里改为纯 TS 实现（RFC 1321），
 * Worker 与测试环境行为一致，可用标准测试向量验证。
 *
 * MD5 在本项目仅用于会话/订阅 token 派生（沿用原设计），不作安全哈希用途。
 * 原实现为 async（crypto.subtle 是 Promise），现为同步；移植调用方时去掉 await。
 */

/** 每步循环移位量（RFC 1321：每个 16 步块内 4 元组重复 4 次） */
const S = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
] as const;

/** 常量表 T[i] = floor(|sin(i+1)| × 2^32)（RFC 1321 标准生成式，误差远小于取整边界） */
const K = new Uint32Array(64);
for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296);

function rotl(x: number, n: number): number {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

/** 对原始字节做 MD5（SS 主密钥派生用；原实现为 CF 专有 crypto.subtle.digest('MD5')） */
export function md5Bytes(message: Uint8Array): Uint8Array {
  const byteLen = message.length;
  // 填充：0x80 + 零字节，使 len-8 ≡ 0 (mod 64) 且留出 8 字节长度域
  const paddedLen = (((byteLen + 8) >> 6) + 1) << 6;
  const padded = new Uint8Array(paddedLen);
  padded.set(message);
  padded[byteLen] = 0x80;
  const view = new DataView(padded.buffer);
  const bitLen = byteLen * 8;
  view.setUint32(paddedLen - 8, bitLen % 4294967296, true);
  view.setUint32(paddedLen - 4, Math.floor(bitLen / 4294967296), true);

  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;
  const M = new Uint32Array(16);

  for (let offset = 0; offset < paddedLen; offset += 64) {
    for (let j = 0; j < 16; j++) M[j] = view.getUint32(offset + j * 4, true);
    let A = a0;
    let B = b0;
    let C = c0;
    let D = d0;

    for (let i = 0; i < 64; i++) {
      // 目标寄存器按 a→d→c→b 循环；操作数取当前值（含本块先前步骤的更新）
      const p = i & 3;
      let x: number;
      let y: number;
      let z: number;
      if (p === 0) { x = B; y = C; z = D; }
      else if (p === 1) { x = A; y = B; z = C; }
      else if (p === 2) { x = D; y = A; z = B; }
      else { x = C; y = D; z = A; }

      let f: number;
      if (i < 16) f = (x & y) | (~x & z);
      else if (i < 32) f = (x & z) | (y & ~z);
      else if (i < 48) f = x ^ y ^ z;
      else f = y ^ (x | ~z);

      let g: number;
      if (i < 16) g = i;
      else if (i < 32) g = (5 * i + 1) % 16;
      else if (i < 48) g = (3 * i + 5) % 16;
      else g = (7 * i) % 16;

      const sum = (f + M[g]! + K[i]!) >>> 0;
      const target = p === 0 ? A : p === 1 ? D : p === 2 ? C : B;
      // RFC 1321 步骤：target = rotl(target + F + M[g] + K[i], s) + x（x 为本步另一操作数）
      const updated = (rotl((target + sum) >>> 0, S[i]!) + x) >>> 0;
      if (p === 0) A = updated;
      else if (p === 1) D = updated;
      else if (p === 2) C = updated;
      else B = updated;
    }

    a0 = (a0 + A) >>> 0;
    b0 = (b0 + B) >>> 0;
    c0 = (c0 + C) >>> 0;
    d0 = (d0 + D) >>> 0;
  }

  const out = new Uint8Array(16);
  const outView = new DataView(out.buffer);
  outView.setUint32(0, a0, true);
  outView.setUint32(4, b0, true);
  outView.setUint32(8, c0, true);
  outView.setUint32(12, d0, true);
  return out;
}

function toHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i]!.toString(16).padStart(2, '0');
  return s;
}

/** 单次 MD5，小写十六进制 */
export function md5Hex(text: string): string {
  return toHex(md5Bytes(new TextEncoder().encode(text)));
}

/**
 * 双重 MD5（原 MD5MD5）：md5(md5(input) 十六进制串的 [7,27) 切片)。
 * cookie、userID、订阅 token 均由此派生 —— 算法不可变（兼容红线 #2）。
 */
export function md5Md5(text: string): string {
  const firstHex = md5Hex(text);
  return md5Hex(firstHex.slice(7, 27));
}
