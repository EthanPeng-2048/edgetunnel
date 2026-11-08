/**
 * 认证测试：恒定时间比较 + cookie 公式（兼容红线 #2）。
 */
import { describe, expect, it } from 'vitest';
import { computeAuthCookie, extractAuthCookie, timingSafeEqual, verifyAuthCookie, verifyPassword } from '../src/auth';

describe('timingSafeEqual', () => {
  it('相同字符串返回 true', () => {
    expect(timingSafeEqual('abc123', 'abc123')).toBe(true);
    expect(timingSafeEqual('', '')).toBe(true);
  });

  it('内容不同返回 false', () => {
    expect(timingSafeEqual('abc123', 'abc124')).toBe(false);
    expect(timingSafeEqual('abc', 'xyz')).toBe(false);
  });

  it('长度不同返回 false（含前缀相同的情形）', () => {
    expect(timingSafeEqual('abc', 'abcd')).toBe(false);
    expect(timingSafeEqual('abcd', 'abc')).toBe(false);
    expect(timingSafeEqual('', 'a')).toBe(false);
  });

  it('多字节字符（UTF-8）正确比较', () => {
    expect(timingSafeEqual('测试密码', '测试密码')).toBe(true);
    expect(timingSafeEqual('测试密码', '测试密妈')).toBe(false);
    // 编码字节数不同：'a' vs 'é'（1 vs 2 字节）
    expect(timingSafeEqual('a', 'é')).toBe(false);
  });
});

describe('cookie 公式（MD5MD5(UA + KEY + ADMIN)）', () => {
  it('与 test_rename.mjs 的向量一致', async () => {
    const cookie = await computeAuthCookie('Mozilla/5.0', 'mykey123', 'adminpass');
    expect(cookie).toBe('19052356fd2e465a2faf96d470d036a8');
  });

  it('UA 变化则 cookie 变化', async () => {
    const a = await computeAuthCookie('UA-A', 'key', 'admin');
    const b = await computeAuthCookie('UA-B', 'key', 'admin');
    expect(a).not.toBe(b);
  });
});

describe('extractAuthCookie', () => {
  it('从 Cookie 头提取 auth 值', () => {
    const req = new Request('https://x.test/', { headers: { Cookie: 'foo=1; auth=deadbeef; bar=2' } });
    expect(extractAuthCookie(req)).toBe('deadbeef');
  });

  it('无 auth 返回 null', () => {
    const req = new Request('https://x.test/', { headers: { Cookie: 'foo=1' } });
    expect(extractAuthCookie(req)).toBeNull();
  });

  it('无 Cookie 头返回 null', () => {
    expect(extractAuthCookie(new Request('https://x.test/'))).toBeNull();
  });
});

describe('verifyAuthCookie', () => {
  const UA = 'TestUA/1.0';
  const KEY = 'secret-key';
  const ADMIN = 'admin-pass';

  it('合法 cookie 通过', async () => {
    const cookie = await computeAuthCookie(UA, KEY, ADMIN);
    const req = new Request('https://x.test/', { headers: { 'User-Agent': UA, Cookie: `auth=${cookie}` } });
    expect(await verifyAuthCookie(req, KEY, ADMIN)).toBe(true);
  });

  it('错误 cookie 拒绝', async () => {
    const req = new Request('https://x.test/', { headers: { 'User-Agent': UA, Cookie: 'auth=00000000000000000000000000000000' } });
    expect(await verifyAuthCookie(req, KEY, ADMIN)).toBe(false);
  });

  it('UA 不匹配则拒绝（cookie 绑定 UA）', async () => {
    const cookie = await computeAuthCookie('OtherUA', KEY, ADMIN);
    const req = new Request('https://x.test/', { headers: { 'User-Agent': UA, Cookie: `auth=${cookie}` } });
    expect(await verifyAuthCookie(req, KEY, ADMIN)).toBe(false);
  });

  it('无 cookie 拒绝', async () => {
    const req = new Request('https://x.test/', { headers: { 'User-Agent': UA } });
    expect(await verifyAuthCookie(req, KEY, ADMIN)).toBe(false);
  });
});

describe('verifyPassword（原：去 \\r\\n 后比较）', () => {
  it('完全匹配通过', () => {
    expect(verifyPassword('pass123', 'pass123')).toBe(true);
  });

  it('adminPassword 含换行时清洗后匹配', () => {
    expect(verifyPassword('pass123', 'pass123\r\n')).toBe(true);
    expect(verifyPassword('pass123', 'pass123\n')).toBe(true);
  });

  it('不匹配拒绝', () => {
    expect(verifyPassword('pass123', 'pass124')).toBe(false);
    expect(verifyPassword('', 'pass123')).toBe(false);
  });

  it('null 输入拒绝', () => {
    expect(verifyPassword(null, 'pass123')).toBe(false);
  });
});
