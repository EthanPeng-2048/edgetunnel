/**
 * 传输参数辅助（原 _worker.js getTransportConfig / getTransportPathValue / randomPath）。
 * loadConfig 计算 LINK 时使用；订阅生成（P7 插件）也会复用。
 */
import { getIdentity } from '../services/identity';
import { COMMON_PATH_SEGMENTS } from './path-segments';
import type { Config } from './schema';

export interface TransportConfig {
  type: string;
  pathFieldName: string;
  hostFieldName: string;
}

/** 由配置推导传输类型串与字段名（原 getTransportConfig） */
export function getTransportConfig(cfg: Partial<Config> = {}): TransportConfig {
  const isGrpc = cfg.transport === 'grpc';
  const [identityHeader, identityKey] = getIdentity(cfg.UUID || '');
  const xhttpPaddingJson = {
    xPaddingObfsMode: true,
    xPaddingMethod: 'tokenish',
    xPaddingPlacement: 'queryInHeader',
    xPaddingHeader: identityHeader,
    xPaddingKey: identityKey,
  };
  return {
    type: isGrpc
      ? cfg.grpcMode === 'multi'
        ? 'grpc&mode=multi'
        : 'grpc&mode=gun'
      : cfg.transport === 'xhttp'
        ? `xhttp&mode=stream-one&extra=${encodeURIComponent(JSON.stringify(xhttpPaddingJson))}`
        : 'ws',
    pathFieldName: isGrpc ? 'serviceName' : 'path',
    hostFieldName: isGrpc ? 'authority' : 'host',
  };
}

/** 随机路径段拼接（原 randomPath）：1~3 段随机词打乱拼接 */
export function randomPath(fullNodePath = '/'): string {
  const randomNum = Math.floor(Math.random() * 3 + 1);
  const picked = [...COMMON_PATH_SEGMENTS].sort(() => 0.5 - Math.random()).slice(0, randomNum).join('/');
  if (fullNodePath === '/') return `/${picked}`;
  return `/${picked + fullNodePath.replace('/?', '?')}`;
}

/** 取节点路径值（原 getTransportPathValue）：randomPath 开启时打乱，gRPC 去掉查询串 */
export function getTransportPathValue(cfg: Partial<Config> = {}, nodePath = '/', asBestSubGenerator = false): string {
  const pathValue = asBestSubGenerator ? '/' : cfg.randomPath ? randomPath(nodePath) : nodePath;
  if (cfg.transport !== 'grpc') return pathValue;
  return pathValue.split('?')[0] || '/';
}
