/**
 * 品牌常量与本机标识测试（兼容红线 #4）。
 */
import { describe, expect, it } from 'vitest';
import { BRAND_OWNER, BRAND_PROXYIP, BRAND_TP1_ID, CLUSTER_SUB_UA, EDT_VERSION, VERSION } from '../src/services/brand';
import { getIdentity } from '../src/services/identity';

describe('品牌常量（与原运行结果一致）', () => {
  it('三个品牌值不变', () => {
    expect(BRAND_PROXYIP).toBe('PROXYIP');
    expect(BRAND_OWNER).toBe('cmliu');
    expect(BRAND_TP1_ID).toBe('090227');
  });

  it('CLUSTER_SUB_UA 展开结果不变', () => {
    expect(CLUSTER_SUB_UA).toBe('v2rayN/edgetunnel (https://github.com/cmliu/edgetunnel)');
  });

  it('EDT_VERSION 为 Version 去非数字', () => {
    expect(VERSION).toMatch(/^\d{4}-\d{2}-\d{2} /);
    expect(EDT_VERSION).toBe(Number(VERSION.replace(/\D+/g, '')));
    expect(Number.isFinite(EDT_VERSION)).toBe(true);
  });
});

describe('getIdentity（uuid 切片派生）', () => {
  const uuid = '01234567-89ab-cdef-0123-456789abcdef';

  it('header = uuid[1..7)', () => {
    const [header] = getIdentity(uuid);
    expect(header).toBe('123456');
  });

  it("key = '_' + uuid[25..31)", () => {
    const [, key] = getIdentity(uuid);
    // uuid = '01234567-89ab-cdef-0123-456789abcdef'，索引 25..31 = '56789a'
    expect(key).toBe('_56789a');
  });

  it('两个 uuid 产生不同标识', () => {
    const a = getIdentity('00000000-0000-4000-8000-000000000000');
    const b = getIdentity('ffffffff-ffff-4fff-bfff-ffffffffffff');
    expect(a[0]).not.toBe(b[0]);
    expect(a[1]).not.toBe(b[1]);
  });
});
