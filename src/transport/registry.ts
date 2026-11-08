/**
 * 传输注册表与选择（DESIGN.md §4.6 评分择优在传输层的应用）。
 *
 * 新增传输：新子类 → registerTransport() → Router 经 selectTransport() 自动分发。
 * 评分档（与原 fetch 分发顺序等价）：WS=100 > gRPC=80 > xHTTP=60；全 0 → 非代理请求。
 */
import { Registry, pickBest } from '../registry';
import type { RequestContext } from '../context';
import { Transport, type TransportSession } from './base';
import { WebSocketTransport } from './websocket';
import { GrpcTransport } from './grpc';
import { XhttpTransport } from './xhttp';

export const transportRegistry = new Registry<Transport>()
  .register(new WebSocketTransport())
  .register(new GrpcTransport())
  .register(new XhttpTransport());

/** 按评分选传输（分高者胜，同分先注册；全 0 返回 undefined → 走 HTTP 路由） */
export function selectTransport(request: Request, ctx: RequestContext): Transport | undefined {
  return pickBest(transportRegistry.list(), (t) => t.score(request, ctx));
}

export type { TransportSession };
