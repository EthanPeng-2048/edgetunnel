/**
 * MD5 / MD5MD5 测试。
 * 向量由 Node crypto（createHash('md5')）生成，覆盖空串、多块填充边界、UTF-8。
 */
import { describe, expect, it } from 'vitest';
import { md5Hex, md5Md5 } from '../src/services/md5';

describe('md5Hex', () => {
  const cases: Array<[input: string, expected: string]> = [
    ['', 'd41d8cd98f00b204e9800998ecf8427e'],
    ['abc', '900150983cd24fb0d6963f7d28e17f72'],
    ['message digest', 'f96b697d7cb7938d525a2f31aaf161d0'],
    ['The quick brown fox jumps over the lazy dog', '9e107d9d372bb6826bd81d3542a419d6'],
    // 填充边界：55/56/64 字节跨块
    ['a'.repeat(55), 'ef1772b6dff9a122358552954ad0df65'],
    ['a'.repeat(56), '3b0c8ac703f828b04c6c197006d17218'],
    ['a'.repeat(64), '014842d480b571495a4a0363793f7367'],
    ['a'.repeat(1000), 'cabe45dcc9ae5b66ba86600cca6b8ba8'],
    // UTF-8 多字节
    ['你好，世界', 'dbefd3ada018615b35588a01e216ae6e'],
    ['admin-secret-测试', '61964916caf3f61b1a6ec0d38261164c'],
  ];

  for (const [input, expected] of cases) {
    const label = input.length > 20 ? `${JSON.stringify(input.slice(0, 10))}…len=${input.length}` : JSON.stringify(input);
    it(`md5(${label})`, () => {
      expect(md5Hex(input)).toBe(expected);
    });
  }
});

describe('md5Md5（双重 MD5，兼容红线 #2）', () => {
  const cases: Array<[input: string, expected: string]> = [
    ['', 'aff32af07c8396c1bef6afd510eb32a6'],
    ['abc', 'f576baf8247333f9d23d9c5a71714f19'],
    ['message digest', '8a01ffc229365fb637a6b6e1a6bb7cf4'],
    ['The quick brown fox jumps over the lazy dog', '1d9f3c07e4823d8400b9f60fead09ce3'],
    ['a'.repeat(55), '11a44cd0a547fe51bb881be2a731bb6e'],
    ['a'.repeat(56), 'db249d8a83c877de5e239f3482c6082d'],
    ['a'.repeat(64), 'feda2b5ae01a62c3bb2ad3cf8f1d3737'],
    ['a'.repeat(1000), '3d472eb3765943a473fd685d5d734a67'],
    ['你好，世界', '617912b9b536a2fa0cf66d8b7b41a624'],
    ['admin-secret-测试', '6cfb2837b720c294ef95a4b52ab48145'],
    // cookie 公式样例：MD5MD5(UA + KEY + ADMIN)
    ['Mozilla/5.0mykey123adminpass', '19052356fd2e465a2faf96d470d036a8'],
  ];

  for (const [input, expected] of cases) {
    const label = input.length > 20 ? `${JSON.stringify(input.slice(0, 10))}…len=${input.length}` : JSON.stringify(input);
    it(`md5Md5(${label})`, () => {
      expect(md5Md5(input)).toBe(expected);
    });
  }
});
