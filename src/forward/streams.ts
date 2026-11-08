/**
 * 双向管道（原 _worker.js connectStreams，行为等价移植）。
 *
 * remoteSocket ↔ ClientLikeSocket 对拷；下行经 Grain 分帧；
 * retryFunc 由 forwarder 注入断线重连（直连失败 → 链式/反代）。
 */
import type { RemoteConn } from './generation';
import { createDownlinkGrainSender, DOWNLINK_GRAIN_CHUNK_BYTES, type ClientLikeSocket, type DownlinkSender } from './grain';

function closeSocketQuietly(socket: ClientLikeSocket): void {
  try {
    if (socket.readyState === 1 || socket.readyState === 2) {
      socket.close?.();
    }
  } catch {
    /* ignore */
  }
}

interface RemoteSocketLike {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  closed?: Promise<unknown>;
  close?(): void;
}

/**
 * 启动 remote ↔ client 双向泵。
 * headerData：首段需前置的协议响应头（VLESS [version,0]），或取头函数（只取一次）。
 * isCurrentSocket：世代校验（generation + socket 身份）。
 */
export async function connectStreams(
  remoteSocket: RemoteSocketLike,
  webSocket: ClientLikeSocket,
  headerData: Uint8Array | null | (() => Uint8Array | null),
  retryFunc: (() => Promise<void>) | null,
  isCurrentSocket: (() => boolean) | null = null,
  remoteConn: RemoteConn | null = null,
): Promise<void> {
  let hasData = false;
  let readError: unknown = null;
  let useBYOB = false;
  const byobReadLimit = 64 * 1024;
  const isCurrentConnectionValid = () => !isCurrentSocket || isCurrentSocket();

  const downlinkSender: DownlinkSender = createDownlinkGrainSender(webSocket, headerData, isCurrentConnectionValid);
  const downlinkController = { stopAndFlush: () => downlinkSender.stopAndFlush() };
  if (remoteConn) remoteConn.downlinkController = downlinkController;
  try {
    void remoteSocket.closed?.catch?.(() => {});
  } catch {
    /* ignore */
  }

  let reader: ReadableStreamDefaultReader<Uint8Array> | ReadableStreamBYOBReader;
  try {
    reader = remoteSocket.readable.getReader({ mode: 'byob' }) as ReadableStreamBYOBReader;
    useBYOB = true;
  } catch {
    reader = remoteSocket.readable.getReader();
  }

  try {
    if (!useBYOB) {
      const defaultReader = reader as ReadableStreamDefaultReader<Uint8Array>;
      for (;;) {
        const { done, value } = await defaultReader.read();
        if (!isCurrentConnectionValid()) break;
        if (done) break;
        if (!value || value.byteLength === 0) continue;
        hasData = true;
        if (value.byteLength >= DOWNLINK_GRAIN_CHUNK_BYTES) {
          await downlinkSender.flush();
          await downlinkSender.sendDirectly(value);
        } else {
          await downlinkSender.send(value);
        }
      }
    } else {
      const byobReader = reader as ReadableStreamBYOBReader;
      let readBuffer = new ArrayBuffer(byobReadLimit);
      for (;;) {
        const { done, value } = await byobReader.read(new Uint8Array(readBuffer, 0, byobReadLimit));
        if (!isCurrentConnectionValid()) break;
        if (done) break;
        if (!value || value.byteLength === 0) continue;
        hasData = true;
        if (value.byteLength >= DOWNLINK_GRAIN_CHUNK_BYTES) {
          await downlinkSender.flush();
          await downlinkSender.sendDirectly(value.slice());
          readBuffer = new ArrayBuffer(byobReadLimit);
        } else {
          await downlinkSender.send(value.slice());
          readBuffer = value.buffer.byteLength >= byobReadLimit ? value.buffer : new ArrayBuffer(byobReadLimit);
        }
      }
    }
    if (isCurrentConnectionValid()) await downlinkSender.flush();
  } catch (err) {
    readError = err;
  } finally {
    if (isCurrentConnectionValid() && webSocket.readyState === 1) {
      try {
        await downlinkSender.stopAndFlush();
      } catch (err) {
        readError ||= err;
      }
    }
    if (remoteConn?.downlinkController === downlinkController) remoteConn.downlinkController = null;
    try {
      await reader.cancel();
    } catch {
      /* ignore */
    }
    try {
      reader.releaseLock();
    } catch {
      /* ignore */
    }
    try {
      remoteSocket.close?.();
    } catch {
      /* ignore */
    }
  }

  // 无下行数据且连接仍有效 → 触发重试（原：直连建立但对端无响应 → 转链式/反代）
  if (!hasData && retryFunc && webSocket.readyState === 1 && isCurrentConnectionValid()) {
    try {
      await retryFunc();
      return;
    } catch (err) {
      readError ||= err;
    }
  }
  if (!isCurrentConnectionValid()) return;
  if (readError) console.error('[TCP下行] 读取失败:', readError);
  closeSocketQuietly(webSocket);
}
