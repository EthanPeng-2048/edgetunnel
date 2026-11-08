/**
 * 协议层基类（DESIGN.md §4.3）。
 *
 * 统一接口：sniff 评分嗅探 → parse 解析首包 → codec 流编解码。
 * 新增协议 = 新子类 + 注册表注册，转发核心零改动。
 *
 * 编排约定（P5 会话编排器遵循）：
 *   rawFirst → protocol.sniff(rawFirst, hints) 评分选协议
 *            → protocol.codec(hints) 建编解码器
 *            → codec.uplink(rawFirst) 得到首段**明文**（VLESS/Trojan 直通，SS 解密；
 *              SS 握手未完成时返回空数组，需继续读流重试）
 *            → protocol.parse(首段明文, hints) 解析目标
 */
import { pickBest } from '../registry';

/** 协议处理上下文（原实现三个 handler 都闭包持有 yourUUID，此处显式传入） */
export interface ProtocolHints {
  /** 用户 ID：VLESS 校验 UUID / Trojan SHA224 密码 / SS 主密钥密码（三者均用 yourUUID） */
  readonly userId: string;
  /** URL 查询参数 —— 仅 WebSocket 传输传入；SS 靠 ?enc= 识别与选加密套件 */
  readonly query?: URLSearchParams;
}

/** 解析结果（原三个 parse 函数返回值的公共形状） */
export interface ParsedRequest {
  host: string;
  port: number;
  udp: boolean;
  /** 协议头之后的剩余客户端数据（首包载荷） */
  payload: Uint8Array;
  /** 需先写回客户端的响应头（VLESS: [version,0]；Trojan/SS 无） */
  replyHeader?: Uint8Array;
}

/**
 * 双向流编解码器（每连接一实例，持有会话密钥/计数器状态）。
 * uplink 返回 0..n 个明文块：0 表示数据仍在缓冲（SS 握手/分帧未齐）。
 */
export interface DuplexCodec {
  uplink(cipher: Uint8Array): Promise<Uint8Array[]>;
  downlink(plain: Uint8Array): Promise<Uint8Array[]>;
}

/** 直通编解码器（VLESS/Trojan：应用层无加密，TLS 之下即明文） */
export const passthroughCodec: DuplexCodec = {
  uplink: async (c) => (c.byteLength > 0 ? [c] : []),
  downlink: async (c) => (c.byteLength > 0 ? [c] : []),
};

/** 嗅探评分常量（互不相同，pickBest 无平局；VLESS 恒为兜底分） */
export const SNIFF_SS = 0.9; // 仅 ?enc= 存在时（原 WS 分支优先级最高）
export const SNIFF_TROJAN = 0.8; // 首包 ≥58 且 [56..57]=CRLF
export const SNIFF_VLESS = 0.5; // 恒定兜底（原实现：非 trojan 非 ss 即 vless）

export abstract class Protocol {
  abstract readonly name: string;

  /** 首包嗅探评分：0 = 不匹配；解析阶段才做密码/UUID 校验 */
  abstract sniff(first: Uint8Array, hints: ProtocolHints): number;

  /** 解析**明文**首包为目标地址；失败抛 TunnelError(PROTOCOL_*) */
  abstract parse(first: Uint8Array, hints: ProtocolHints): ParsedRequest;

  /** 每连接编解码器；默认直通，SS 覆写为 AEAD 状态机 */
  codec(_hints: ProtocolHints): DuplexCodec {
    return passthroughCodec;
  }
}
