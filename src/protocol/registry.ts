/**
 * 协议注册表与选择（DESIGN.md §4.6 评分择优在协议层的应用）。
 *
 * 新增协议：新子类 → registerProtocol() → 编排器经 selectProtocol() 自动识别。
 */
import { Registry, pickBest } from '../registry';
import { Protocol, type ProtocolHints } from './base';
import { VlessProtocol } from './vless';
import { TrojanProtocol } from './trojan';
import { ShadowsocksProtocol } from './shadowsocks';

export const protocolRegistry = new Registry<Protocol>()
  .register(new VlessProtocol())
  .register(new TrojanProtocol())
  .register(new ShadowsocksProtocol());

/**
 * 按首包评分选协议（分高者胜，同分先注册优先；VLESS 恒为兜底分，必有结果）。
 * 编排器拿到协议后走 codec → parse 流程（见 base.ts 编排约定）。
 */
export function selectProtocol(first: Uint8Array, hints: ProtocolHints): Protocol | undefined {
  return pickBest(protocolRegistry.list(), (p) => p.sniff(first, hints));
}
