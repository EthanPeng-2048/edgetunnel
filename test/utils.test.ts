/**
 * 字节与数组工具测试（行为对齐原 _worker.js 纯函数）。
 */
import { describe, expect, it } from 'vitest';
import { concatByteChunks, effectiveByteLength, toUint8Array } from '../src/utils/bytes';
import { asArray, ensureArray } from '../src/utils/array';

describe('toUint8Array', () => {
  it('Uint8Array 原样返回（同一引用）', () => {
    const u8 = new Uint8Array([1, 2, 3]);
    expect(toUint8Array(u8)).toBe(u8);
  });

  it('ArrayBuffer 转换', () => {
    const buf = new Uint8Array([4, 5]).buffer;
    expect([...toUint8Array(buf)]).toEqual([4, 5]);
  });

  it('TypedArray 视图按 byteOffset/byteLength 切片', () => {
    const full = new Uint8Array([9, 1, 2, 9]);
    const view = new Uint8Array(full.buffer, 1, 2);
    expect([...toUint8Array(view)]).toEqual([1, 2]);
  });

  it('number 视为长度（零填充）', () => {
    expect(toUint8Array(3)).toEqual(new Uint8Array(3));
  });

  it('无法识别的输入返回空数组', () => {
    expect(toUint8Array(null)).toEqual(new Uint8Array(0));
    expect(toUint8Array(undefined)).toEqual(new Uint8Array(0));
    expect(toUint8Array('str')).toEqual(new Uint8Array(0));
  });
});

describe('concatByteChunks', () => {
  it('顺序拼接多个块', () => {
    const result = concatByteChunks(new Uint8Array([1, 2]), new Uint8Array([3]), new Uint8Array([4, 5, 6]));
    expect([...result]).toEqual([1, 2, 3, 4, 5, 6]);
  });

  it('无参数返回空数组', () => {
    expect(concatByteChunks()).toEqual(new Uint8Array(0));
  });

  it('混合 ArrayBuffer 与视图', () => {
    const result = concatByteChunks(new Uint8Array([1]).buffer, new Uint8Array([2, 3]));
    expect([...result]).toEqual([1, 2, 3]);
  });
});

describe('effectiveByteLength', () => {
  it('byteLength 优先', () => {
    expect(effectiveByteLength(new Uint8Array(7))).toBe(7);
  });

  it('string 走 length', () => {
    expect(effectiveByteLength('hello')).toBe(5);
  });

  it('假值返回 0', () => {
    expect(effectiveByteLength(null)).toBe(0);
    expect(effectiveByteLength(undefined)).toBe(0);
    expect(effectiveByteLength('')).toBe(0);
  });

  it('无长度属性返回 0', () => {
    expect(effectiveByteLength({})).toBe(0);
  });
});

describe('ensureArray（逗号/引号/换行分隔拆分）', () => {
  it('普通逗号分隔', () => {
    expect(ensureArray('a,b,c')).toEqual(['a', 'b', 'c']);
  });

  it('引号、换行、制表符折叠为分隔（空格不在字符类，前导空格保留 —— 原行为）', () => {
    expect(ensureArray('"a"\n b\tc')).toEqual(['a', ' b', 'c']);
  });

  it('连续逗号合并、首尾逗号掐除', () => {
    expect(ensureArray(',a,,b,')).toEqual(['a', 'b']);
  });

  it('单元素', () => {
    expect(ensureArray('solo')).toEqual(['solo']);
  });

  it('空串返回 [""]（与原实现一致）', () => {
    expect(ensureArray('')).toEqual(['']);
  });
});

describe('asArray（单值/数组归一化）', () => {
  it('null/undefined → []', () => {
    expect(asArray(null)).toEqual([]);
    expect(asArray(undefined)).toEqual([]);
  });

  it('数组原样', () => {
    const arr = [1, 2];
    expect(asArray(arr)).toBe(arr);
  });

  it('单值包成数组', () => {
    expect(asArray(5)).toEqual([5]);
    expect(asArray('x')).toEqual(['x']);
  });
});
