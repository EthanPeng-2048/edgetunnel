/**
 * Trojan 协议（原 parseTrojanRequest，行为等价移植）。
 *
 * 首包布局：sha224hexASCII(56) | CRLF(2) | cmd(1) | atype(1) | addr | port(2) | CRLF(2) | payload
 * 嗅探：首包 ≥58 且 [56..57] == CRLF；密码校验在 parse 阶段（sha224 明文逐字节比对）。
 */
import { Protocol, SNIFF_TROJAN, type ParsedRequest, type ProtocolHints } from './base';
import { TunnelError } from '../errors';
import { toUint8Array } from '../utils/bytes';
import { sha224 } from '../utils/sha224';

const trojanTextDecoder = new TextDecoder();

export class TrojanProtocol extends Protocol {
  readonly name = 'trojan';

  override sniff(first: Uint8Array, _hints: ProtocolHints): number {
    return first.byteLength >= 58 && first[56] === 0x0d && first[57] === 0x0a ? SNIFF_TROJAN : 0;
  }

  override parse(first: Uint8Array, hints: ProtocolHints): ParsedRequest {
    const data = toUint8Array(first);
    const sha224Password = sha224(hints.userId);
    if (data.byteLength < 58) throw new TunnelError('PROTOCOL_TROJAN_INVALID_DATA', 'invalid data');
    const crLfIndex = 56;
    if (data[crLfIndex] !== 0x0d || data[crLfIndex + 1] !== 0x0a) throw new TunnelError('PROTOCOL_TROJAN_INVALID_HEADER', 'invalid header format');
    for (let i = 0; i < crLfIndex; i++) {
      if (data[i] !== sha224Password.charCodeAt(i)) throw new TunnelError('PROTOCOL_TROJAN_INVALID_PASSWORD', 'invalid password');
    }

    const socks5Index = crLfIndex + 2;
    if (data.byteLength < socks5Index + 6) throw new TunnelError('PROTOCOL_TROJAN_INVALID_DATA', 'invalid S5 request data');

    const cmd = data[socks5Index]!;
    if (cmd !== 1 && cmd !== 3) throw new TunnelError('PROTOCOL_TROJAN_INVALID_COMMAND', 'unsupported command, only TCP/UDP is allowed');
    const isUDP = cmd === 3;

    const atype = data[socks5Index + 1]!;
    let addressLength = 0;
    let addressIndex = socks5Index + 2;
    let address = '';
    switch (atype) {
      case 1: // IPv4
        addressLength = 4;
        if (data.byteLength < addressIndex + addressLength + 4) throw new TunnelError('PROTOCOL_TROJAN_INVALID_DATA', 'invalid S5 request data');
        address = `${data[addressIndex]}.${data[addressIndex + 1]}.${data[addressIndex + 2]}.${data[addressIndex + 3]}`;
        break;
      case 3: {
        // 域名
        if (data.byteLength < addressIndex + 1) throw new TunnelError('PROTOCOL_TROJAN_INVALID_DATA', 'invalid S5 request data');
        addressLength = data[addressIndex]!;
        addressIndex += 1;
        if (data.byteLength < addressIndex + addressLength + 4) throw new TunnelError('PROTOCOL_TROJAN_INVALID_DATA', 'invalid S5 request data');
        address = trojanTextDecoder.decode(data.subarray(addressIndex, addressIndex + addressLength));
        break;
      }
      case 4: {
        // IPv6
        addressLength = 16;
        if (data.byteLength < addressIndex + addressLength + 4) throw new TunnelError('PROTOCOL_TROJAN_INVALID_DATA', 'invalid S5 request data');
        const ipv6: string[] = [];
        for (let i = 0; i < 8; i++) {
          const partIndex = addressIndex + i * 2;
          ipv6.push(((data[partIndex]! << 8) | data[partIndex + 1]!).toString(16));
        }
        address = ipv6.join(':');
        break;
      }
      default:
        throw new TunnelError('PROTOCOL_TROJAN_INVALID_ADDR_TYPE', `invalid addressType is ${atype}`);
    }

    if (!address) throw new TunnelError('PROTOCOL_TROJAN_INVALID_ADDR', `address is empty, addressType is ${atype}`);

    const portIndex = addressIndex + addressLength;
    if (data.byteLength < portIndex + 4) throw new TunnelError('PROTOCOL_TROJAN_INVALID_DATA', 'invalid S5 request data');
    const port = (data[portIndex]! << 8) | data[portIndex + 1]!;

    return {
      host: address,
      port,
      udp: isUDP,
      payload: data.subarray(portIndex + 4),
    };
  }
}
