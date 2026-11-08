/**
 * Shadowsocks 协议（原 getSsContext / handleSsData 地址段，行为等价移植）。
 *
 * 与 VLESS/Trojan 的结构差异（编排契约，见 base.ts）：
 *  - sniff 只看 URL ?enc=（gRPC/xHTTP 不传 query → 永不命中，与原实现一致）；
 *  - parse 作用于**解密后的首个明文块**（地址段在 AEAD 载荷内）；
 *  - codec 是有状态的（入站 salt 握手 + 长度/载荷分帧解密；出站独立 salt + 分帧加密）。
 *
 * 明文首块布局（SOCKS5 地址类型）：atype(1) | addr | port(2) | payload
 *   atype 1=IPv4(4) / 3=域名(1+len) / 4=IPv6(16) —— 注意域名是 3 不是 2。
 */
import { Protocol, SNIFF_SS, type DuplexCodec, type ParsedRequest, type ProtocolHints } from './base';
import { TunnelError } from '../errors';
import { concatByteChunks, toUint8Array } from '../utils/bytes';
import {
  SS_AEAD_TAG_LEN,
  SS_NONCE_LEN,
  ssAeadDecrypt,
  ssAeadEncrypt,
  ssCandidateConfigs,
  ssDeriveMasterKey,
  ssDeriveSessionKey,
  type SsCipherConfig,
} from './ss-crypto';

const ssTextDecoder = new TextDecoder();

/** 入站/出站共享的分帧常量（原 L1482/L1504） */
const SS_LENGTH_CIPHER_LEN = 2 + SS_AEAD_TAG_LEN; // 18
const SS_MAX_ALIGN_SCAN_BYTES = 16;

/**
 * 每连接 SS 编解码器。
 * uplink：原始密文 → 明文块（0 块 = 握手/分帧数据未齐，编排器继续读流）。
 * downlink：明文 → 密文块（首次调用前置出站 salt，即使载荷为空 —— 原 encryptAndSend 语义）。
 */
class SsCodec implements DuplexCodec {
  // —— 入站状态（原 inboundState）——
  private buffer: Uint8Array = new Uint8Array(0);
  private hasSalt = false;
  private waitPayloadLength: number | null = null;
  private decryptKey: CryptoKey | null = null;
  private readonly nonceCounter = new Uint8Array(SS_NONCE_LEN);
  private cryptoConfig: SsCipherConfig | null = null;
  private readonly candidates: SsCipherConfig[];
  private readonly encLabel: string;

  // —— 出站状态（原 outboundCipher，惰性初始化）——
  private outbound: {
    config: SsCipherConfig;
    key: CryptoKey;
    salt: Uint8Array;
    nonce: Uint8Array;
    saltSent: boolean;
  } | null = null;

  constructor(
    private readonly userId: string,
    encMethod: string | null | undefined,
  ) {
    this.candidates = ssCandidateConfigs(encMethod);
    this.encLabel = (encMethod || '').toLowerCase() || 'auto';
  }

  /**
   * 原 initInboundDecryptState：扫描 0..16B 前导噪声对齐，逐候选套件试解长度帧。
   * 返回 true=握手完成；false=数据不足（继续缓冲）；确定性失败抛 PROTOCOL_SS_HANDSHAKE_FAILED。
   */
  private async initAsync(): Promise<boolean> {
    const maxSaltLen = Math.max(...this.candidates.map((c) => c.saltLen));
    const minSaltLen = Math.min(...this.candidates.map((c) => c.saltLen));
    const maxScanOffset = Math.min(SS_MAX_ALIGN_SCAN_BYTES, Math.max(0, this.buffer.byteLength - (SS_LENGTH_CIPHER_LEN + minSaltLen)));

    for (let offset = 0; offset <= maxScanOffset; offset++) {
      for (const config of this.candidates) {
        const initMinLength = offset + config.saltLen + SS_LENGTH_CIPHER_LEN;
        if (this.buffer.byteLength < initMinLength) continue;
        const salt = this.buffer.subarray(offset, offset + config.saltLen);
        const lengthCipher = this.buffer.subarray(offset + config.saltLen, initMinLength);
        const masterKey = ssDeriveMasterKey(this.userId, config.keyLen);
        try {
          const decryptKey = await ssDeriveSessionKey(config, masterKey, salt, ['decrypt']);
          const nonce = new Uint8Array(SS_NONCE_LEN);
          const lengthPlain = await ssAeadDecrypt(decryptKey, nonce, lengthCipher);
          if (lengthPlain.byteLength !== 2) continue;
          const payloadLength = (lengthPlain[0]! << 8) | lengthPlain[1]!;
          if (payloadLength < 0 || payloadLength > config.maxChunk) continue;
          // 原实现命中后记录前导噪声/套件切换日志（log() 为 debug 门控，此处省略，不影响解密行为）
          this.buffer = this.buffer.subarray(initMinLength);
          this.decryptKey = decryptKey;
          this.nonceCounter.set(nonce);
          this.waitPayloadLength = payloadLength;
          this.cryptoConfig = config;
          this.hasSalt = true;
          return true;
        } catch {
          // 该候选失败 → 下一候选
        }
      }
    }
    const initFailGuessLength = maxSaltLen + SS_LENGTH_CIPHER_LEN + SS_MAX_ALIGN_SCAN_BYTES;
    if (this.buffer.byteLength >= initFailGuessLength) {
      throw new TunnelError(
        'PROTOCOL_SS_HANDSHAKE_FAILED',
        `SS handshake decrypt failed (enc=${this.encLabel}, candidates=${this.candidates.map((c) => c.method).join('/')})`,
      );
    }
    return false;
  }

  async uplink(cipher: Uint8Array): Promise<Uint8Array[]> {
    const chunk = toUint8Array(cipher);
    if (chunk.byteLength > 0) this.buffer = concatByteChunks(this.buffer, chunk);
    if (!this.hasSalt) {
      const initSuccess = await this.initAsync();
      if (!initSuccess) return [];
    }

    const plaintextChunks: Uint8Array[] = [];
    const key = this.decryptKey!;
    while (true) {
      if (this.waitPayloadLength === null) {
        if (this.buffer.byteLength < SS_LENGTH_CIPHER_LEN) break;
        const lengthCipher = this.buffer.subarray(0, SS_LENGTH_CIPHER_LEN);
        this.buffer = this.buffer.subarray(SS_LENGTH_CIPHER_LEN);
        let lengthPlain: Uint8Array;
        try {
          lengthPlain = await ssAeadDecrypt(key, this.nonceCounter, lengthCipher);
        } catch (err) {
          throw new TunnelError('PROTOCOL_SS_DECRYPT_FAILED', 'SS length decrypt failed', err);
        }
        if (lengthPlain.byteLength !== 2) throw new TunnelError('PROTOCOL_SS_LENGTH_INVALID', 'SS length decrypt failed');
        const payloadLength = (lengthPlain[0]! << 8) | lengthPlain[1]!;
        if (payloadLength < 0 || payloadLength > this.cryptoConfig!.maxChunk) {
          throw new TunnelError('PROTOCOL_SS_PAYLOAD_INVALID', `SS payload length invalid: ${payloadLength}`);
        }
        this.waitPayloadLength = payloadLength;
      }
      const payloadCipherTotalLength = this.waitPayloadLength + SS_AEAD_TAG_LEN;
      if (this.buffer.byteLength < payloadCipherTotalLength) break;
      const payloadCipher = this.buffer.subarray(0, payloadCipherTotalLength);
      this.buffer = this.buffer.subarray(payloadCipherTotalLength);
      let payloadPlain: Uint8Array;
      try {
        payloadPlain = await ssAeadDecrypt(key, this.nonceCounter, payloadCipher);
      } catch (err) {
        throw new TunnelError('PROTOCOL_SS_DECRYPT_FAILED', 'Decryption failed', err);
      }
      plaintextChunks.push(payloadPlain);
      this.waitPayloadLength = null;
    }
    return plaintextChunks;
  }

  async downlink(plain: Uint8Array): Promise<Uint8Array[]> {
    const out: Uint8Array[] = [];
    if (!this.outbound) {
      if (!this.cryptoConfig) throw new TunnelError('PROTOCOL_SS_NOT_NEGOTIATED', 'SS cipher is not negotiated');
      const config = this.cryptoConfig;
      const masterKey = ssDeriveMasterKey(this.userId, config.keyLen);
      const salt = crypto.getRandomValues(new Uint8Array(config.saltLen));
      const key = await ssDeriveSessionKey(config, masterKey, salt, ['encrypt']);
      this.outbound = { config, key, salt, nonce: new Uint8Array(SS_NONCE_LEN), saltSent: false };
    }
    const ob = this.outbound;
    if (!ob.saltSent) {
      out.push(ob.salt);
      ob.saltSent = true;
    }
    const plaintextData = toUint8Array(plain);
    if (plaintextData.byteLength === 0) return out;

    let offset = 0;
    while (offset < plaintextData.byteLength) {
      const end = Math.min(offset + ob.config.maxChunk, plaintextData.byteLength);
      const payloadPlain = plaintextData.subarray(offset, end);
      const lengthPlain = new Uint8Array(2);
      lengthPlain[0] = (payloadPlain.byteLength >>> 8) & 0xff;
      lengthPlain[1] = payloadPlain.byteLength & 0xff;
      const lengthCipher = await ssAeadEncrypt(ob.key, ob.nonce, lengthPlain);
      const payloadCipher = await ssAeadEncrypt(ob.key, ob.nonce, payloadPlain);
      out.push(concatByteChunks(lengthCipher, payloadCipher));
      offset = end;
    }
    return out;
  }
}

export class ShadowsocksProtocol extends Protocol {
  readonly name = 'ss';

  override sniff(_first: Uint8Array, hints: ProtocolHints): number {
    // 原 WS 分支：url.searchParams.get('enc') 真值才判 SS；gRPC/xHTTP 不传 query → 0
    return hints.query?.get('enc') ? SNIFF_SS : 0;
  }

  /**
   * 解析**解密后首个明文块**（原 handleSsData 地址段）。
   * 编排契约：codec.uplink 首个非空批次的第 0 块交给 parse，其余块作为后续载荷直接转发。
   */
  override parse(first: Uint8Array, _hints: ProtocolHints): ParsedRequest {
    const plainData = toUint8Array(first);
    if (plainData.byteLength < 3) throw new TunnelError('PROTOCOL_SS_INVALID_DATA', 'invalid ss data');
    const addressType = plainData[0]!;
    let cursor = 1;
    let hostname = '';
    if (addressType === 1) {
      if (plainData.byteLength < cursor + 4 + 2) throw new TunnelError('PROTOCOL_SS_INVALID_IPV4', 'invalid ss ipv4 length');
      hostname = `${plainData[cursor]}.${plainData[cursor + 1]}.${plainData[cursor + 2]}.${plainData[cursor + 3]}`;
      cursor += 4;
    } else if (addressType === 3) {
      if (plainData.byteLength < cursor + 1) throw new TunnelError('PROTOCOL_SS_INVALID_DOMAIN', 'invalid ss domain length');
      const domainLength = plainData[cursor]!;
      cursor += 1;
      if (plainData.byteLength < cursor + domainLength + 2) throw new TunnelError('PROTOCOL_SS_INVALID_DOMAIN', 'invalid ss domain data');
      hostname = ssTextDecoder.decode(plainData.subarray(cursor, cursor + domainLength));
      cursor += domainLength;
    } else if (addressType === 4) {
      if (plainData.byteLength < cursor + 16 + 2) throw new TunnelError('PROTOCOL_SS_INVALID_IPV6', 'invalid ss ipv6 length');
      const ipv6: string[] = [];
      const ipv6View = new DataView(plainData.buffer, plainData.byteOffset + cursor, 16);
      for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16));
      hostname = ipv6.join(':');
      cursor += 16;
    } else {
      throw new TunnelError('PROTOCOL_SS_INVALID_ADDR_TYPE', `invalid ss addressType: ${addressType}`);
    }
    if (!hostname) throw new TunnelError('PROTOCOL_SS_INVALID_ADDR', `invalid ss address: ${addressType}`);
    const port = (plainData[cursor]! << 8) | plainData[cursor + 1]!;
    cursor += 2;
    const payload = plainData.subarray(cursor);
    // SS 在本实现中仅走 TCP（原 handleSsData 恒 forwardataTCP）
    return { host: hostname, port, udp: false, payload };
  }

  override codec(hints: ProtocolHints): DuplexCodec {
    return new SsCodec(hints.userId, hints.query?.get('enc'));
  }
}
