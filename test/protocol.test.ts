/**
 * P3 协议层测试 —— 首包向量 + SS 用 Node crypto 独立构造密文交叉验证。
 * 覆盖：sha224 / SS 密钥派生 / VLESS·Trojan·SS 解析 / 嗅探评分 / selectProtocol。
 */
import { describe, expect, it } from 'vitest';
import { createCipheriv, createDecipheriv, createHash, createHmac } from 'node:crypto';
import { sha224 } from '../src/utils/sha224';
import { SS_CIPHER_CONFIGS, ssDeriveMasterKey } from '../src/protocol/ss-crypto';
import { VlessProtocol } from '../src/protocol/vless';
import { TrojanProtocol } from '../src/protocol/trojan';
import { ShadowsocksProtocol } from '../src/protocol/shadowsocks';
import { selectProtocol } from '../src/protocol/registry';
import { SNIFF_SS, SNIFF_TROJAN, SNIFF_VLESS, type ProtocolHints } from '../src/protocol/base';
import { TunnelError } from '../src/errors';

const USER_ID = '00000000-0000-4000-8000-000000000000';
const hints: ProtocolHints = { userId: USER_ID };

function uuidToBytes(uuid: string): Uint8Array {
  const clean = uuid.replace(/-/g, '');
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytes(...values: number[]): Uint8Array {
  return new Uint8Array(values);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.byteLength, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.byteLength;
  }
  return out;
}

describe('sha224（与 Node crypto 交叉验证）', () => {
  const vectors: Array<[input: string, expected: string]> = [
    ['', 'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f'],
    ['abc', '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7'],
    [USER_ID, '8da1399d0f9af7d3c60ca98c6fb067576d705ab325f37869d2b53ae8'],
  ];
  for (const [input, expected] of vectors) {
    it(`sha224(${JSON.stringify(input.slice(0, 20))}${input.length > 20 ? '…' : ''})`, () => {
      expect(sha224(input)).toBe(expected);
      expect(sha224(input)).toBe(createHash('sha224').update(input).digest('hex'));
    });
  }

  it('多块输入（>64B 触发第二轮压缩）', () => {
    const input = 'a'.repeat(200);
    expect(sha224(input)).toBe(createHash('sha224').update(input).digest('hex'));
  });
});

describe('SS 密钥派生（与 Node crypto 交叉验证）', () => {
  it('主密钥 keyLen=16 = MD5(password)', () => {
    const key = ssDeriveMasterKey(USER_ID, 16);
    expect(Buffer.from(key).toString('hex')).toBe(createHash('md5').update(USER_ID).digest('hex'));
    expect(Buffer.from(key).toString('hex')).toBe('6e9036f9d52b7ac8faea061c38033ffe');
  });

  it('主密钥 keyLen=32 = MD5链两轮', () => {
    const key = ssDeriveMasterKey(USER_ID, 32);
    expect(Buffer.from(key).toString('hex')).toBe('6e9036f9d52b7ac8faea061c38033ffed06ac6de409dd79903677c3d34244cb5');
  });

  it('主密钥缓存返回同一引用', () => {
    expect(ssDeriveMasterKey(USER_ID, 16)).toBe(ssDeriveMasterKey(USER_ID, 16));
  });
});

// —— SS 独立构造器：全部用 Node crypto，避免与被测代码同源 ——

function nodeSsMasterKey(pw: string, keyLen: number): Buffer {
  let prev = Buffer.alloc(0);
  let result = Buffer.alloc(0);
  while (result.length < keyLen) {
    prev = createHash('md5').update(Buffer.concat([prev, Buffer.from(pw)])).digest();
    result = Buffer.concat([result, prev]);
  }
  return result.subarray(0, keyLen);
}

function nodeSsSessionKey(masterKey: Buffer, salt: Buffer, keyLen: number): Buffer {
  const prk = createHmac('sha1', salt).update(masterKey).digest();
  let prev = Buffer.alloc(0);
  let out = Buffer.alloc(0);
  let counter = 1;
  while (out.length < keyLen) {
    prev = createHmac('sha1', prk)
      .update(Buffer.concat([prev, Buffer.from('ss-subkey'), Buffer.from([counter])]))
      .digest();
    out = Buffer.concat([out, prev]);
    counter++;
  }
  return out.subarray(0, keyLen);
}

function nodeAeadEncrypt(key: Buffer, nonce: Buffer, plain: Buffer): Buffer {
  const cipher = createCipheriv('aes-128-gcm', key, nonce);
  const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
  return Buffer.concat([ct, cipher.getAuthTag()]);
}

function nodeAeadDecrypt(key: Buffer, nonce: Buffer, frame: Buffer): Buffer {
  const decipher = createDecipheriv('aes-128-gcm', key, nonce);
  decipher.setAuthTag(frame.subarray(frame.length - 16));
  return Buffer.concat([decipher.update(frame.subarray(0, frame.length - 16)), decipher.final()]);
}

/** 独立构造 SS 上行包：salt | AEAD(len) | AEAD(payload)，nonce 0→1 */
function buildSsUplink(userId: string, plain: Uint8Array, noise: Uint8Array = new Uint8Array(0)): Uint8Array {
  const config = SS_CIPHER_CONFIGS['aes-128-gcm']!;
  const masterKey = nodeSsMasterKey(userId, config.keyLen);
  const salt = Buffer.from('0123456789abcdef', 'utf8'); // 16B
  const key = nodeSsSessionKey(masterKey, salt, config.keyLen);
  const nonce = Buffer.alloc(12);
  const lengthPlain = Buffer.from([(plain.byteLength >> 8) & 0xff, plain.byteLength & 0xff]);
  const lengthCipher = nodeAeadEncrypt(key, nonce, lengthPlain);
  nonce[0] = 1; // 小端计数器 +1（与 ssIncrementNonce 一致：先加 byte0）
  const payloadCipher = nodeAeadEncrypt(key, nonce, Buffer.from(plain));
  return concat(noise, new Uint8Array(salt), new Uint8Array(lengthCipher), new Uint8Array(payloadCipher));
}

function ssDomainPlain(host: string, port: number, payload: Uint8Array): Uint8Array {
  const hostBytes = new TextEncoder().encode(host);
  return concat(bytes(3, hostBytes.length), hostBytes, bytes((port >> 8) & 0xff, port & 0xff), payload);
}

describe('VLESS 解析', () => {
  const vless = new VlessProtocol();

  function buildVless(opts: { version?: number; cmd?: number; addrType: number; addr: Uint8Array; payload?: Uint8Array; optLen?: number }): Uint8Array {
    const version = opts.version ?? 0;
    const optLen = opts.optLen ?? 0;
    const port = 443;
    return concat(
      bytes(version),
      uuidToBytes(USER_ID),
      bytes(optLen),
      new Uint8Array(optLen), // options
      bytes(opts.cmd ?? 1, (port >> 8) & 0xff, port & 0xff, opts.addrType),
      opts.addr,
      opts.payload ?? new Uint8Array(0),
    );
  }

  it('域名地址 + TCP → host/port/payload/replyHeader', () => {
    const payload = new TextEncoder().encode('hello');
    const addr = concat(bytes(11), new TextEncoder().encode('example.com'));
    const first = buildVless({ addrType: 2, addr, payload });
    const parsed = vless.parse(first, hints);
    expect(parsed.host).toBe('example.com');
    expect(parsed.port).toBe(443);
    expect(parsed.udp).toBe(false);
    expect(new TextDecoder().decode(parsed.payload)).toBe('hello');
    expect([...parsed.replyHeader!]).toEqual([0, 0]);
  });

  it('IPv4 地址', () => {
    const first = buildVless({ addrType: 1, addr: bytes(1, 2, 3, 4) });
    const parsed = vless.parse(first, hints);
    expect(parsed.host).toBe('1.2.3.4');
    expect(parsed.port).toBe(443);
  });

  it('IPv6 地址', () => {
    const addr = new Uint8Array(16);
    addr[15] = 1; // ::1
    const parsed = vless.parse(buildVless({ addrType: 3, addr }), hints);
    expect(parsed.host).toBe('0:0:0:0:0:0:0:1');
  });

  it('UDP 命令 (cmd=2)', () => {
    const parsed = vless.parse(buildVless({ cmd: 2, addrType: 1, addr: bytes(8, 8, 8, 8) }), hints);
    expect(parsed.udp).toBe(true);
  });

  it('replyHeader 携带 version', () => {
    const parsed = vless.parse(buildVless({ version: 1, addrType: 1, addr: bytes(1, 1, 1, 1) }), hints);
    expect([...parsed.replyHeader!]).toEqual([1, 0]);
  });

  it('错误 UUID → PROTOCOL_VLESS_INVALID_UUID', () => {
    const first = buildVless({ addrType: 1, addr: bytes(1, 2, 3, 4) });
    first[1] = 0xff; // 破坏 UUID 首字节
    expect(() => vless.parse(first, hints)).toThrow(TunnelError);
    try {
      vless.parse(first, hints);
    } catch (err) {
      expect((err as TunnelError).code).toBe('PROTOCOL_VLESS_INVALID_UUID');
    }
  });

  it('过短首包 → PROTOCOL_VLESS_INVALID_DATA', () => {
    expect(() => vless.parse(bytes(0, 1, 2), hints)).toThrow(/Invalid data/);
  });

  it('非法命令 → PROTOCOL_VLESS_INVALID_COMMAND', () => {
    expect(() => vless.parse(buildVless({ cmd: 9, addrType: 1, addr: bytes(1, 2, 3, 4) }), hints)).toThrow(/Invalid command/);
  });

  it('非法地址类型 → PROTOCOL_VLESS_INVALID_ADDR_TYPE', () => {
    // 首包需 ≥24 字节才不会提前命中 Invalid data
    expect(() => vless.parse(buildVless({ addrType: 7, addr: bytes(1, 2, 3, 4, 5, 6, 7, 8) }), hints)).toThrow(/Invalid address type/);
  });
});

describe('Trojan 解析', () => {
  const trojan = new TrojanProtocol();

  function buildTrojan(opts: { cmd?: number; atype: number; addr: Uint8Array; payload?: Uint8Array; password?: string }): Uint8Array {
    const hashHex = sha224(opts.password ?? USER_ID);
    const hashAscii = new TextEncoder().encode(hashHex); // 56B
    const port = 8443;
    return concat(
      hashAscii,
      bytes(0x0d, 0x0a),
      bytes(opts.cmd ?? 1, opts.atype),
      opts.addr,
      bytes((port >> 8) & 0xff, port & 0xff),
      bytes(0x0d, 0x0a),
      opts.payload ?? new Uint8Array(0),
    );
  }

  it('域名 + TCP → host/port/payload', () => {
    const payload = new TextEncoder().encode('data');
    const addr = concat(bytes(11), new TextEncoder().encode('example.org'));
    const parsed = trojan.parse(buildTrojan({ atype: 3, addr, payload }), hints);
    expect(parsed.host).toBe('example.org');
    expect(parsed.port).toBe(8443);
    expect(parsed.udp).toBe(false);
    expect(new TextDecoder().decode(parsed.payload)).toBe('data');
    expect(parsed.replyHeader).toBeUndefined();
  });

  it('IPv4 地址', () => {
    const parsed = trojan.parse(buildTrojan({ atype: 1, addr: bytes(192, 168, 1, 1) }), hints);
    expect(parsed.host).toBe('192.168.1.1');
    expect(parsed.port).toBe(8443);
  });

  it('UDP 命令 (cmd=3)', () => {
    const parsed = trojan.parse(buildTrojan({ cmd: 3, atype: 1, addr: bytes(1, 1, 1, 1) }), hints);
    expect(parsed.udp).toBe(true);
  });

  it('密码不匹配 → PROTOCOL_TROJAN_INVALID_PASSWORD', () => {
    const first = buildTrojan({ atype: 1, addr: bytes(1, 2, 3, 4), password: 'wrong-password' });
    try {
      trojan.parse(first, hints);
      expect.unreachable('应当抛错');
    } catch (err) {
      expect((err as TunnelError).code).toBe('PROTOCOL_TROJAN_INVALID_PASSWORD');
    }
  });

  it('CRLF 位置错误 → PROTOCOL_TROJAN_INVALID_HEADER', () => {
    const first = buildTrojan({ atype: 1, addr: bytes(1, 2, 3, 4) });
    first[56] = 0x00;
    expect(() => trojan.parse(first, hints)).toThrow(/invalid header format/);
  });

  it('非法命令 → PROTOCOL_TROJAN_INVALID_COMMAND', () => {
    expect(() => trojan.parse(buildTrojan({ cmd: 5, atype: 1, addr: bytes(1, 2, 3, 4) }), hints)).toThrow(/unsupported command/);
  });
});

describe('SS 解析与编解码（Node crypto 独立构造交叉验证）', () => {
  const ss = new ShadowsocksProtocol();

  it('sniff：有 ?enc= → SNIFF_SS；无 → 0', () => {
    expect(ss.sniff(new Uint8Array(0), { userId: USER_ID, query: new URLSearchParams('enc=aes-128-gcm') })).toBe(SNIFF_SS);
    expect(ss.sniff(new Uint8Array(0), hints)).toBe(0);
  });

  it('uplink 解密独立构造的包 → parse 得到目标', async () => {
    const payload = new TextEncoder().encode('ss-payload');
    const plain = ssDomainPlain('ss.example.com', 8080, payload);
    const packet = buildSsUplink(USER_ID, plain);

    const codec = ss.codec({ userId: USER_ID, query: new URLSearchParams('enc=aes-128-gcm') });
    const chunks = await codec.uplink(packet);
    expect(chunks.length).toBe(1);
    const parsed = ss.parse(chunks[0]!, hints);
    expect(parsed.host).toBe('ss.example.com');
    expect(parsed.port).toBe(8080);
    expect(parsed.udp).toBe(false);
    expect(new TextDecoder().decode(parsed.payload)).toBe('ss-payload');
  });

  it('uplink 支持前导噪声对齐（0..16B 扫描）', async () => {
    const plain = ssDomainPlain('noise.example.com', 9, bytes(1, 2, 3));
    const noise = bytes(0xaa, 0xbb, 0xcc, 0xdd);
    const packet = buildSsUplink(USER_ID, plain, noise);

    const codec = ss.codec({ userId: USER_ID, query: new URLSearchParams('enc=aes-128-gcm') });
    const chunks = await codec.uplink(packet);
    expect(chunks.length).toBe(1);
    expect(ss.parse(chunks[0]!, hints).host).toBe('noise.example.com');
  });

  it('uplink 分片：握手数据不足时返回空数组，补齐后出明文', async () => {
    const plain = ssDomainPlain('split.example.com', 443, bytes(9));
    const packet = buildSsUplink(USER_ID, plain);

    const codec = ss.codec({ userId: USER_ID, query: new URLSearchParams('enc=aes-128-gcm') });
    const half = packet.subarray(0, 10);
    const rest = packet.subarray(10);
    expect(await codec.uplink(half)).toEqual([]);
    const chunks = await codec.uplink(rest);
    expect(chunks.length).toBe(1);
    expect(ss.parse(chunks[0]!, hints).host).toBe('split.example.com');
  });

  it('downlink 出站 salt + 分帧，Node 可独立解密', async () => {
    const plain = ssDomainPlain('up.example.com', 443, bytes(7, 7));
    const packet = buildSsUplink(USER_ID, plain);
    const codec = ss.codec({ userId: USER_ID, query: new URLSearchParams('enc=aes-128-gcm') });
    await codec.uplink(packet); // 完成握手，协商 cryptoConfig

    const serverData = new TextEncoder().encode('server-response');
    const out = await codec.downlink(serverData);
    expect(out.length).toBe(2); // salt + 1 frame
    const salt = Buffer.from(out[0]!);
    const frame = Buffer.from(out[1]!);
    expect(salt.length).toBe(16);

    const masterKey = nodeSsMasterKey(USER_ID, 16);
    const key = nodeSsSessionKey(masterKey, salt, 16);
    // 帧 = AEAD_len(nonce=0) || AEAD_payload(nonce=1)，需分段解密
    const lengthFrame = frame.subarray(0, 18);
    const payloadFrame = frame.subarray(18);
    const nonce0 = Buffer.alloc(12);
    const lengthPlain = nodeAeadDecrypt(key, nonce0, lengthFrame);
    expect(lengthPlain.length).toBe(2);
    const nonce1 = Buffer.alloc(12);
    nonce1[0] = 1;
    const decrypted = nodeAeadDecrypt(key, nonce1, payloadFrame);
    expect(decrypted.toString('utf8')).toBe('server-response');
  });

  it('downlink 首次调用即输出 salt（即使载荷为空）', async () => {
    const plain = ssDomainPlain('x.com', 80, bytes(1));
    const codec = ss.codec({ userId: USER_ID, query: new URLSearchParams('enc=aes-128-gcm') });
    await codec.uplink(buildSsUplink(USER_ID, plain));
    const out = await codec.downlink(new Uint8Array(0));
    expect(out.length).toBe(1);
    expect(out[0]!.length).toBe(16);
  });

  it('未握手先 downlink → PROTOCOL_SS_NOT_NEGOTIATED', async () => {
    const codec = ss.codec(hints);
    await expect(codec.downlink(bytes(1))).rejects.toThrow(/not negotiated/);
  });

  it('错误密码 → 握手确定性失败 PROTOCOL_SS_HANDSHAKE_FAILED', async () => {
    const plain = ssDomainPlain('bad.example.com', 80, bytes(1));
    const packet = buildSsUplink('ffffffff-ffff-4fff-bfff-ffffffffffff', plain); // 不同密码
    const codec = ss.codec({ userId: USER_ID, query: new URLSearchParams('enc=aes-128-gcm') });
    try {
      await codec.uplink(packet);
      expect.unreachable('应当抛错');
    } catch (err) {
      expect((err as TunnelError).code).toBe('PROTOCOL_SS_HANDSHAKE_FAILED');
    }
  });

  it('IPv4 明文地址解析', () => {
    const plain = concat(bytes(1, 10, 0, 0, 1, 0x1f, 0x90), new Uint8Array(5));
    const parsed = ss.parse(plain, hints);
    expect(parsed.host).toBe('10.0.0.1');
    expect(parsed.port).toBe(8080);
    expect(parsed.payload.byteLength).toBe(5);
  });

  it('过短明文 → PROTOCOL_SS_INVALID_DATA', () => {
    expect(() => ss.parse(bytes(3, 65), hints)).toThrow(/invalid ss data/);
  });
});

describe('嗅探评分与 selectProtocol', () => {
  it('VLESS 恒为兜底分', () => {
    expect(new VlessProtocol().sniff(new Uint8Array(0), hints)).toBe(SNIFF_VLESS);
  });

  it('Trojan：CRLF 模式 → SNIFF_TROJAN；否则 0', () => {
    const trojan = new TrojanProtocol();
    const withCrlf = new Uint8Array(60);
    withCrlf[56] = 0x0d;
    withCrlf[57] = 0x0a;
    expect(trojan.sniff(withCrlf, hints)).toBe(SNIFF_TROJAN);
    expect(trojan.sniff(new Uint8Array(60), hints)).toBe(0);
    expect(trojan.sniff(new Uint8Array(10), hints)).toBe(0); // 过短
  });

  it('selectProtocol：?enc= → SS（最高分优先于 Trojan 模式）', () => {
    const withCrlf = new Uint8Array(60);
    withCrlf[56] = 0x0d;
    withCrlf[57] = 0x0a;
    const picked = selectProtocol(withCrlf, { userId: USER_ID, query: new URLSearchParams('enc=aes-128-gcm') });
    expect(picked?.name).toBe('ss');
  });

  it('selectProtocol：CRLF 模式无 enc → trojan', () => {
    const withCrlf = new Uint8Array(60);
    withCrlf[56] = 0x0d;
    withCrlf[57] = 0x0a;
    expect(selectProtocol(withCrlf, hints)?.name).toBe('trojan');
  });

  it('selectProtocol：普通首包 → vless 兜底', () => {
    expect(selectProtocol(bytes(0, 1, 2, 3), hints)?.name).toBe('vless');
  });

  it('评分严格递减：SS > Trojan > VLESS（无平局）', () => {
    expect(SNIFF_SS).toBeGreaterThan(SNIFF_TROJAN);
    expect(SNIFF_TROJAN).toBeGreaterThan(SNIFF_VLESS);
  });
});
