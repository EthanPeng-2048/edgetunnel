/**
 * VLESS 协议（原 parseVlessRequest，行为等价移植）。
 *
 * 首包布局：version(1) | uuid(16) | optLen(1) | options(optLen) | cmd(1) | port(2) | addrType(1) | addr | payload
 * 嗅探：恒为兜底分（原实现：非 trojan 非 ss 即 vless），UUID 校验在 parse 阶段。
 */
import { Protocol, SNIFF_VLESS, type ParsedRequest, type ProtocolHints } from './base';
import { TunnelError } from '../errors';
import { toUint8Array } from '../utils/bytes';
import { uuidBytesMatch } from '../utils/uuid-bytes';

const vlessTextDecoder = new TextDecoder();

export class VlessProtocol extends Protocol {
  readonly name = 'vless';

  override sniff(_first: Uint8Array, _hints: ProtocolHints): number {
    return SNIFF_VLESS;
  }

  override parse(first: Uint8Array, hints: ProtocolHints): ParsedRequest {
    const data = toUint8Array(first);
    const length = data.byteLength;
    if (length < 24) throw new TunnelError('PROTOCOL_VLESS_INVALID_DATA', 'Invalid data');
    const version = data[0]!;
    if (!uuidBytesMatch(data, 1, hints.userId)) throw new TunnelError('PROTOCOL_VLESS_INVALID_UUID', 'Invalid uuid');

    const optLen = data[17]!;
    const cmdIndex = 18 + optLen;
    if (length < cmdIndex + 4) throw new TunnelError('PROTOCOL_VLESS_INVALID_DATA', 'Invalid data');

    const cmd = data[cmdIndex]!;
    let isUDP = false;
    if (cmd === 1) {
      // TCP
    } else if (cmd === 2) {
      isUDP = true;
    } else {
      throw new TunnelError('PROTOCOL_VLESS_INVALID_COMMAND', 'Invalid command');
    }

    const portIdx = cmdIndex + 1;
    const port = (data[portIdx]! << 8) | data[portIdx + 1]!;
    let addrValIdx = portIdx + 3;
    let addrLen = 0;
    let hostname = '';
    const addressType = data[portIdx + 2]!;
    switch (addressType) {
      case 1: // IPv4
        addrLen = 4;
        if (length < addrValIdx + addrLen) throw new TunnelError('PROTOCOL_VLESS_INVALID_IPV4', 'Invalid IPv4 address length');
        hostname = `${data[addrValIdx]}.${data[addrValIdx + 1]}.${data[addrValIdx + 2]}.${data[addrValIdx + 3]}`;
        break;
      case 2: {
        // 域名
        if (length < addrValIdx + 1) throw new TunnelError('PROTOCOL_VLESS_INVALID_DOMAIN', 'Invalid domain length');
        addrLen = data[addrValIdx]!;
        addrValIdx += 1;
        if (length < addrValIdx + addrLen) throw new TunnelError('PROTOCOL_VLESS_INVALID_DOMAIN', 'Invalid domain data');
        hostname = vlessTextDecoder.decode(data.subarray(addrValIdx, addrValIdx + addrLen));
        break;
      }
      case 3: {
        // IPv6
        addrLen = 16;
        if (length < addrValIdx + addrLen) throw new TunnelError('PROTOCOL_VLESS_INVALID_IPV6', 'Invalid IPv6 address length');
        const ipv6: string[] = [];
        for (let i = 0; i < 8; i++) {
          const base = addrValIdx + i * 2;
          ipv6.push(((data[base]! << 8) | data[base + 1]!).toString(16));
        }
        hostname = ipv6.join(':');
        break;
      }
      default:
        throw new TunnelError('PROTOCOL_VLESS_INVALID_ADDR_TYPE', `Invalid address type: ${addressType}`);
    }
    if (!hostname) throw new TunnelError('PROTOCOL_VLESS_INVALID_ADDR', `Invalid address: ${addressType}`);

    const rawIndex = addrValIdx + addrLen;
    return {
      host: hostname,
      port,
      udp: isUDP,
      payload: data.subarray(rawIndex),
      replyHeader: new Uint8Array([version, 0]),
    };
  }
}
