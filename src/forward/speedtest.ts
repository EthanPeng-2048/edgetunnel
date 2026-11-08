/**
 * 测速站点识别与本地 204 响应（原 _worker.js isSpeedTestSite /
 * buildLocal204Response / buildWsLocal204Response）。
 */
import { effectiveByteLength, toUint8Array } from '../utils/bytes';

const SPEED_TEST_DOMAINS = ['speed.cloudflare.com', 'cp.cloudflare.com'];

/** 是否测速站点（原 isSpeedTestSite：精确或子域匹配） */
export function isSpeedTestSite(hostname: string): boolean {
  const host = hostname.toLowerCase();
  return SPEED_TEST_DOMAINS.some((domain) => host === domain || host.endsWith('.' + domain));
}

/** HTTP/1.1 204 No Content（Connection: close）—— 原 buildLocal204Response */
export function buildLocal204Response(respHeader: Uint8Array | null = null): Uint8Array {
  const local204Response = new TextEncoder().encode(
    'HTTP/1.1 204 No Content\r\n' + 'Content-Length: 0\r\n' + 'Connection: close\r\n' + '\r\n',
  );
  if (effectiveByteLength(respHeader) === 0) return local204Response;
  const protocolRespHeader = toUint8Array(respHeader);
  const response = new Uint8Array(protocolRespHeader.byteLength + local204Response.byteLength);
  response.set(protocolRespHeader, 0);
  response.set(local204Response, protocolRespHeader.byteLength);
  return response;
}

/** WS 测速 204（Connection: keep-alive）—— 原 buildWsLocal204Response */
export function buildWsLocal204Response(respHeader: Uint8Array | null = null): Uint8Array {
  const wsLocal204Response = new TextEncoder().encode(
    'HTTP/1.1 204 No Content\r\n' + 'Content-Length: 0\r\n' + 'Connection: keep-alive\r\n' + '\r\n',
  );
  if (effectiveByteLength(respHeader) === 0) return wsLocal204Response;
  const protocolRespHeader = toUint8Array(respHeader);
  const response = new Uint8Array(protocolRespHeader.byteLength + wsLocal204Response.byteLength);
  response.set(protocolRespHeader, 0);
  response.set(wsLocal204Response, protocolRespHeader.byteLength);
  return response;
}
