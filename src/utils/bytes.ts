/**
 * 字节工具（原 _worker.js 章节 4/5 的纯函数，行为等价移植）。
 */

/**
 * 归一化为 Uint8Array。
 * 与原实现的差异说明：原实现兜底 `new Uint8Array(data || 0)`，
 * 对数组类对象走 TypedArray 构造器的 array-like 拷贝；这里显式处理数组，
 * 其余无法识别的输入统一返回空数组（调用方只传 ArrayBuffer / 视图 / number）。
 */
export function toUint8Array(data: unknown): Uint8Array {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  if (typeof data === 'number') return new Uint8Array(data);
  if (Array.isArray(data)) return Uint8Array.from(data.map((n) => Number(n) || 0));
  return new Uint8Array(0);
}

/** 顺序拼接多个字节块（原 concatByteChunks） */
export function concatByteChunks(...chunkList: unknown[]): Uint8Array {
  if (chunkList.length === 0) return new Uint8Array(0);
  const chunks = chunkList.map(toUint8Array);
  let total = 0;
  for (const c of chunks) total += c.byteLength;
  const result = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    result.set(c, offset);
    offset += c.byteLength;
  }
  return result;
}

/**
 * 宽松取长度（原 effectiveByteLength）：
 * 兼容 Uint8Array.byteLength 与 string.length；假值（null/0/''）返回 0。
 */
export function effectiveByteLength(data: unknown): number {
  if (!data) return 0;
  const withByteLength = data as { byteLength?: unknown };
  if (typeof withByteLength.byteLength === 'number') return withByteLength.byteLength;
  const withLength = data as { length?: unknown };
  if (typeof withLength.length === 'number') return withLength.length;
  return 0;
}
