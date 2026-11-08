/**
 * 连接世代管理（原 _worker.js invalidateTcpGeneration / beginTcpGeneration）。
 *
 * 同一 remoteConnWrapper 上的重拨/断线重连通过 generation 计数避免旧 socket 回写。
 */

/** 可携带下行停止钩子的控制器（原 downlinkController） */
export interface DownlinkController {
  stopAndFlush(): Promise<void>;
}

/** 每会话的出站连接状态（原 remoteConnWrapper） */
export interface RemoteConn {
  generation: number;
  socket: unknown | null;
  connectingPromise: Promise<unknown> | null;
  retryConnect: (() => Promise<void>) | null;
  downlinkController: DownlinkController | null;
  downlinkDrain: Promise<unknown>;
}

export function createRemoteConn(): RemoteConn {
  return {
    generation: 0,
    socket: null,
    connectingPromise: null,
    retryConnect: null,
    downlinkController: null,
    downlinkDrain: Promise.resolve(),
  };
}

/** 使当前世代失效并关闭旧 socket（原 invalidateTcpGeneration） */
export function invalidateTcpGeneration(remoteConn: RemoteConn | null | undefined): void {
  if (!remoteConn) return;
  remoteConn.generation = (Number.isInteger(remoteConn.generation) ? remoteConn.generation : 0) + 1;
  const socket = remoteConn.socket;
  remoteConn.socket = null;
  remoteConn.downlinkController = null;
  remoteConn.downlinkDrain = Promise.resolve();
  try {
    (socket as { close?: () => void } | null)?.close?.();
  } catch {
    /* ignore */
  }
}

/**
 * 开启新世代：递增 generation、清空旧 socket、排空旧下行（原 beginTcpGeneration）。
 * 返回 { generation, downlinkDrain } —— 安装新连接前必须 await downlinkDrain。
 */
export function beginTcpGeneration(remoteConn: RemoteConn): { generation: number; downlinkDrain: Promise<unknown> } {
  if (!Number.isInteger(remoteConn.generation)) remoteConn.generation = 0;
  const generation = ++remoteConn.generation;
  const previousSocket = remoteConn.socket;
  remoteConn.socket = null;
  const previousDownlink = remoteConn.downlinkController;
  remoteConn.downlinkController = null;
  const previousDrain = remoteConn.downlinkDrain || Promise.resolve();
  let currentDrain: Promise<unknown>;
  try {
    currentDrain = previousDownlink?.stopAndFlush?.() || Promise.resolve();
  } catch (error) {
    currentDrain = Promise.reject(error);
  }
  const downlinkDrain = Promise.all([previousDrain, currentDrain]);
  // 安装方会 await 此 promise；立即挂 catch 防止 dial 完成前 drain 失败导致 unhandled rejection
  downlinkDrain.catch(() => {});
  remoteConn.downlinkDrain = downlinkDrain;
  try {
    (previousSocket as { close?: () => void } | null)?.close?.();
  } catch {
    /* ignore */
  }
  return { generation, downlinkDrain };
}
