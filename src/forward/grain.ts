/**
 * Grain 合包队列（原 _worker.js createGrainBuffer / createUplinkCoalesceStream /
 * createUplinkWriteQueue / createDownlinkGrainSender，行为等价移植）。
 *
 * 全局调优常量与原实现一致（L27-28）。
 */
import { concatByteChunks, effectiveByteLength, toUint8Array } from '../utils/bytes';

export const WS_EARLY_DATA_MAX_BYTES = 8 * 1024;
export const UPLINK_COALESCE_TARGET_BYTES = 20 * 1024;
export const UPLINK_QUEUE_MAX_BYTES = 16 * 1024 * 1024;
export const UPLINK_QUEUE_MAX_ITEMS = 4096;
export const DOWNLINK_GRAIN_CHUNK_BYTES = 32 * 1024;
export const DOWNLINK_GRAIN_TAIL_THRESHOLD = 512;
export const DOWNLINK_GRAIN_LOW_WATER_BYTES = Math.max(4096, DOWNLINK_GRAIN_TAIL_THRESHOLD * 12);
export const DOWNLINK_GRAIN_MAX_WAIT_ROUNDS = 4;

// —— 定长环形缓冲（原 createGrainBuffer）——

interface GrainItem {
  chunk: Uint8Array;
  allowRetry?: boolean;
  completions?: Array<{ resolve: () => void; reject: (e: unknown) => void }> | null;
}

export interface GrainBuffer {
  readonly byteCount: number;
  readonly entryCount: number;
  readonly isEmpty: boolean;
  clear(processItem?: (item: GrainItem) => void): void;
  absorb(item: GrainItem): boolean;
  coalesce(): { chunk: Uint8Array; items: GrainItem[] } | null;
}

export function createGrainBuffer(capacity: number, copyCoalesceResult = false): GrainBuffer {
  let queue: Array<GrainItem | undefined> = [];
  let head = 0;
  let byteCount = 0;
  let coalesceBuffer: Uint8Array | null = null;

  const isEmpty = () => head >= queue.length;
  const compressed = () => {
    if (head > 32 && head * 2 >= queue.length) {
      queue = queue.slice(head);
      head = 0;
    }
  };
  const take = (): GrainItem | null => {
    if (isEmpty()) return null;
    const item = queue[head]!;
    queue[head++] = undefined;
    byteCount -= item.chunk.byteLength;
    compressed();
    return item;
  };

  return {
    get byteCount() {
      return byteCount;
    },
    get entryCount() {
      return queue.length - head;
    },
    get isEmpty() {
      return isEmpty();
    },
    clear(processItem) {
      if (processItem) {
        for (let i = head; i < queue.length; i++) {
          if (queue[i]) processItem(queue[i]!);
        }
      }
      queue = [];
      head = 0;
      byteCount = 0;
    },
    absorb(item) {
      if (!item?.chunk?.byteLength) return false;
      queue.push(item);
      byteCount += item.chunk.byteLength;
      return true;
    },
    coalesce() {
      const first = take();
      if (!first) return null;
      const items = [first];
      if (isEmpty() || first.chunk.byteLength >= capacity) return { chunk: first.chunk, items };

      let totalBytes = first.chunk.byteLength;
      let end = head;
      while (end < queue.length) {
        const nextBytes = totalBytes + queue[end]!.chunk.byteLength;
        if (nextBytes > capacity) break;
        totalBytes = nextBytes;
        end++;
      }
      if (end === head) return { chunk: first.chunk, items };

      const output = (coalesceBuffer ||= new Uint8Array(capacity));
      output.set(first.chunk, 0);
      let offset = first.chunk.byteLength;
      while (head < end) {
        const next = queue[head]!;
        queue[head++] = undefined;
        byteCount -= next.chunk.byteLength;
        items.push(next);
        output.set(next.chunk, offset);
        offset += next.chunk.byteLength;
      }
      compressed();
      const bundled = output.subarray(0, totalBytes);
      return { chunk: copyCoalesceResult ? bundled.slice() : bundled, items };
    },
  };
}

// —— 上行合包流（原 createUplinkCoalesceStream）——

export interface UplinkCoalescer {
  readonly readable: ReadableStream<Uint8Array>;
  write(chunk: Uint8Array): Promise<void>;
  end(): Promise<void>;
}

export function createUplinkCoalesceStream(targetBytes = UPLINK_COALESCE_TARGET_BYTES): UplinkCoalescer {
  const identity = typeof IdentityTransformStream !== 'undefined' ? new IdentityTransformStream() : new TransformStream<Uint8Array, Uint8Array>();
  const writer = identity.writable.getWriter();
  const buffer = new Uint8Array(targetBytes);
  let bufferLength = 0;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let inflightWrites: Promise<void> | null = null;
  let flushChain: Promise<void> = Promise.resolve();

  const cleanupTimer = () => {
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
  };

  const serialWrite = async (chunk: Uint8Array) => {
    if (inflightWrites) await inflightWrites;
    inflightWrites = writer.write(chunk);
    try {
      await inflightWrites;
    } finally {
      inflightWrites = null;
    }
  };

  const flush = async () => {
    if (bufferLength) {
      const chunk = buffer.slice(0, bufferLength);
      bufferLength = 0;
      await serialWrite(chunk);
    }
  };

  const queueFlush = () => {
    flushChain = flushChain
      .then(() => flush())
      .catch(() => {});
  };

  const startTimer = () => {
    if (timer) return;
    timer = setTimeout(() => {
      timer = null;
      queueFlush();
    }, 1);
  };

  return {
    readable: identity.readable,
    write: async (chunk) => {
      const data = toUint8Array(chunk);
      if (!data.byteLength) return;
      if (data.byteLength >= targetBytes) {
        cleanupTimer();
        if (bufferLength) await flush();
        await serialWrite(data);
        return;
      }
      if (bufferLength + data.byteLength >= targetBytes) {
        const output = new Uint8Array(bufferLength + data.byteLength);
        output.set(buffer.subarray(0, bufferLength), 0);
        output.set(data, bufferLength);
        bufferLength = 0;
        cleanupTimer();
        await serialWrite(output);
      } else {
        buffer.set(data, bufferLength);
        bufferLength += data.byteLength;
        startTimer();
      }
    },
    end: async () => {
      cleanupTimer();
      try {
        await flushChain;
        await flush();
        await writer.close();
      } finally {
        try {
          writer.releaseLock();
        } catch {
          /* ignore */
        }
      }
    },
  };
}

// —— 上行写入队列（原 createUplinkWriteQueue）——

export interface UplinkQueueOptions {
  getWriter: () => WritableStreamDefaultWriter<Uint8Array> | null;
  getConnectTask?: (() => Promise<unknown> | null) | null;
  releaseWriter?: (() => void) | null;
  retryConnect?: (() => Promise<void>) | null;
  closeConnection?: ((err: unknown) => void) | null;
  queueName?: string;
}

export interface UplinkWriteQueue {
  write(data: Uint8Array | ArrayBuffer | ArrayBufferView, allowRetry?: boolean): boolean;
  writeAndWait(data: Uint8Array | ArrayBuffer | ArrayBufferView, allowRetry?: boolean): Promise<boolean>;
  waitIdle(): Promise<void>;
  clear(): void;
}

export function createUplinkWriteQueue(options: UplinkQueueOptions): UplinkWriteQueue {
  const { getWriter, getConnectTask = null, releaseWriter, retryConnect, closeConnection, queueName = '上行队列' } = options;
  const grain = createGrainBuffer(UPLINK_COALESCE_TARGET_BYTES);
  let draining = false;
  let closed = false;
  let idleResolvers: Array<() => void> = [];
  let activeCompletions: Array<{ resolve: () => void; reject: (e: unknown) => void }> | null = null;

  const settleCompletions = (completions: Array<{ resolve: () => void; reject: (e: unknown) => void }> | null | undefined, err: unknown = null) => {
    if (!completions) return;
    for (const completion of completions) {
      if (err) completion.reject(err);
      else completion.resolve();
    }
  };

  const resolveIdle = () => {
    if (grain.byteCount || draining || !idleResolvers.length) return;
    const resolvers = idleResolvers;
    idleResolvers = [];
    for (const resolve of resolvers) resolve();
  };

  const clear = (err: unknown = null) => {
    const closeErr = err || (closed ? new Error(`${queueName}: queue closed`) : null);
    if (closeErr) {
      grain.clear((item) => settleCompletions(item.completions, closeErr));
      settleCompletions(activeCompletions, closeErr);
      activeCompletions = null;
    } else grain.clear();
    resolveIdle();
  };

  const bundle = () => {
    const packed = grain.coalesce();
    if (!packed) return null;
    let allowRetry = true;
    let completions: Array<{ resolve: () => void; reject: (e: unknown) => void }> | null = null;
    for (const item of packed.items) {
      allowRetry = allowRetry && item.allowRetry !== false;
      if (item.completions) completions = completions ? completions.concat(item.completions) : item.completions;
    }
    return { chunk: packed.chunk, allowRetry, completions };
  };

  const waitForAvailableWriter = async () => {
    let writer = getWriter();
    if (writer) return writer;
    const connectionTask = getConnectTask?.();
    if (connectionTask) await connectionTask;
    return getWriter();
  };

  const drain = async () => {
    if (draining || closed) return;
    draining = true;
    try {
      for (;;) {
        if (closed) break;
        const item = bundle();
        if (!item) break;
        const completions = item.completions || null;
        activeCompletions = completions;
        try {
          let writer = await waitForAvailableWriter();
          if (closed) break;
          if (!writer) throw new Error(`${queueName}: remote writer unavailable`);
          try {
            await writer.write(item.chunk);
          } catch (err) {
            releaseWriter?.();
            if (closed) break;
            if (!item.allowRetry || typeof retryConnect !== 'function') throw err;
            await retryConnect();
            if (closed) break;
            writer = getWriter();
            if (!writer) throw err;
            await writer.write(item.chunk);
          }
          settleCompletions(completions);
        } catch (err) {
          settleCompletions(completions, err);
          throw err;
        } finally {
          if (activeCompletions === completions) activeCompletions = null;
        }
      }
    } catch (err) {
      closed = true;
      clear(err);
      console.error(`[${queueName}] 写入失败:`, err);
      try {
        closeConnection?.(err);
      } catch {
        /* ignore */
      }
    } finally {
      draining = false;
      if (!closed && !grain.isEmpty) void drain();
      else resolveIdle();
    }
  };

  const enqueue = (data: Uint8Array | ArrayBuffer | ArrayBufferView, allowRetry: boolean, waitForFlush: boolean): boolean | Promise<boolean> => {
    if (closed) return false;
    // 首包解析阶段既没有 writer 也没有连接任务；返回 false 交给上层继续协议解析。
    if (!getWriter() && !getConnectTask?.()) return false;
    const chunk = toUint8Array(data);
    if (!chunk.byteLength) return true;
    const nextBytes = grain.byteCount + chunk.byteLength;
    const nextItems = grain.entryCount + 1;
    if (nextBytes > UPLINK_QUEUE_MAX_BYTES || nextItems > UPLINK_QUEUE_MAX_ITEMS) {
      closed = true;
      const err = Object.assign(new Error(`${queueName}: upload queue overflow (${nextBytes}B/${nextItems})`), { isQueueOverflow: true });
      clear(err);
      console.error(`[${queueName}] 队列超限，关闭连接`);
      try {
        closeConnection?.(err);
      } catch {
        /* ignore */
      }
      throw err;
    }
    let completionPromise: Promise<boolean> | null = null;
    let completions: Array<{ resolve: () => void; reject: (e: unknown) => void }> | null = null;
    if (waitForFlush) {
      completions = [];
      completionPromise = new Promise<boolean>((resolve, reject) => {
        completions!.push({
          resolve: () => resolve(true),
          reject,
        });
      });
    }
    grain.absorb({ chunk, allowRetry, completions });
    if (!draining) void drain();
    return waitForFlush ? completionPromise! : true;
  };

  return {
    write(data, allowRetry = true) {
      return enqueue(data, allowRetry, false) as boolean;
    },
    writeAndWait(data, allowRetry = true) {
      return Promise.resolve(enqueue(data, allowRetry, true));
    },
    async waitIdle() {
      if (!grain.byteCount && !draining) return;
      await new Promise<void>((resolve) => idleResolvers.push(resolve));
    },
    clear() {
      closed = true;
      clear();
    },
  };
}

// —— 下行 Grain 发送器（原 createDownlinkGrainSender）——

/** 类 WebSocket 的下行适配器（WS / gRPC 桥 / xHTTP 桥共用） */
export interface ClientLikeSocket {
  readyState: number;
  send(data: Uint8Array | ArrayBuffer | ArrayBufferView): void;
  close?(): void;
}

export interface DownlinkSender {
  sendDirectly(data: Uint8Array): Promise<void>;
  send(data: Uint8Array): Promise<void>;
  flush(): Promise<void>;
  stopAndFlush(): Promise<void>;
}

const WS_OPEN = 1;
const WS_CLOSING = 2;

function closeSocketQuietly(socket: ClientLikeSocket): void {
  try {
    if (socket.readyState === WS_OPEN || socket.readyState === WS_CLOSING) {
      socket.close?.();
    }
  } catch {
    /* ignore */
  }
}

function wsSendAndWait(socket: ClientLikeSocket, payload: Uint8Array): Promise<void> {
  const sendResult = socket.send(payload) as unknown;
  if (sendResult && typeof (sendResult as Promise<void>).then === 'function') return sendResult as Promise<void>;
  return Promise.resolve();
}

export function createDownlinkGrainSender(
  webSocket: ClientLikeSocket,
  headerData: Uint8Array | null | (() => Uint8Array | null) = null,
  isActive: (() => boolean) | null = null,
): DownlinkSender {
  const packetCap = DOWNLINK_GRAIN_CHUNK_BYTES;
  const tailBytes = DOWNLINK_GRAIN_TAIL_THRESHOLD;
  const grain = createGrainBuffer(packetCap, true);
  let header = typeof headerData === 'function' ? null : headerData;
  const getResponseHeader =
    typeof headerData === 'function'
      ? headerData
      : () => {
          const value = header;
          header = null;
          return value;
        };
  let flushTimer: ReturnType<typeof setTimeout> | null = null;
  let generation = 0;
  let scheduledGeneration = 0;
  let waitRounds = 0;
  let flushPromise: Promise<void> | null = null;
  let directSendPromise: Promise<void> | null = null;
  let forceDrain = false;
  let stopStarted = false;
  let activeSendCount = 0;
  let activeDirectSendCount = 0;
  let activeSendError: unknown = null;
  let activeSendWaiters: Array<() => void> = [];

  const waitForActiveSends = () => {
    if (!activeSendCount && !activeDirectSendCount) return Promise.resolve();
    return new Promise<void>((resolve) => activeSendWaiters.push(resolve));
  };
  const markSendDone = () => {
    if (activeSendCount || activeDirectSendCount || !activeSendWaiters.length) return;
    const resolvers = activeSendWaiters;
    activeSendWaiters = [];
    for (const resolve of resolvers) resolve();
  };
  const checkActiveSendError = () => {
    if (!activeSendError) return;
    const err = activeSendError;
    grain.clear();
    throw err;
  };
  const currentSenderActive = () => forceDrain || !isActive || isActive();
  const closeActiveConnections = () => {
    if (currentSenderActive()) closeSocketQuietly(webSocket);
  };

  const extraRespHeader = (chunk: Uint8Array): Uint8Array => {
    const responseHeader = getResponseHeader();
    if (!responseHeader) return chunk;
    const merged = new Uint8Array(responseHeader.length + chunk.byteLength);
    merged.set(responseHeader, 0);
    merged.set(chunk, responseHeader.length);
    return merged;
  };

  const sendRawChunk = async (chunk: Uint8Array) => {
    if (!currentSenderActive()) return;
    if (webSocket.readyState !== WS_OPEN) throw new Error('ws.readyState is not open');
    const out = extraRespHeader(chunk);
    await wsSendAndWait(webSocket, out);
  };

  const serialSendRawChunk = async (chunk: Uint8Array) => {
    while (directSendPromise) await directSendPromise;
    const sendTask = sendRawChunk(chunk);
    directSendPromise = sendTask;
    try {
      await sendTask;
    } finally {
      if (directSendPromise === sendTask) directSendPromise = null;
    }
  };

  const flush = async (): Promise<void> => {
    while (flushPromise) await flushPromise;
    if (flushTimer) clearTimeout(flushTimer);
    flushTimer = null;
    waitRounds = 0;
    if (!currentSenderActive()) {
      grain.clear();
      return;
    }
    const sendTask = (async () => {
      for (;;) {
        if (!currentSenderActive()) {
          grain.clear();
          break;
        }
        const packed = grain.coalesce();
        if (!packed) break;
        await serialSendRawChunk(packed.chunk);
      }
    })();
    flushPromise = sendTask
      .catch((err) => {
        activeSendError ||= err;
        throw err;
      })
      .finally(() => {
        flushPromise = null;
      });
    return flushPromise;
  };

  const scheduleFlush = () => {
    if (!currentSenderActive()) {
      grain.clear();
      return;
    }
    if (grain.isEmpty || flushTimer) return;
    if (grain.byteCount >= packetCap || packetCap - grain.byteCount < tailBytes) {
      flush().catch(closeActiveConnections);
      return;
    }
    flushTimer = setTimeout(() => {
      flushTimer = null;
      if (!currentSenderActive()) {
        grain.clear();
        return;
      }
      if (grain.isEmpty) return;
      if (grain.byteCount >= packetCap || packetCap - grain.byteCount < tailBytes) {
        flush().catch(closeActiveConnections);
        return;
      }
      if (waitRounds < DOWNLINK_GRAIN_MAX_WAIT_ROUNDS && (generation !== scheduledGeneration || grain.byteCount < DOWNLINK_GRAIN_LOW_WATER_BYTES)) {
        waitRounds++;
        scheduledGeneration = generation;
        scheduleFlush();
        return;
      }
      flush().catch(closeActiveConnections);
    }, 1);
  };

  return {
    async sendDirectly(data) {
      if (stopStarted || !currentSenderActive()) return;
      activeDirectSendCount++;
      try {
        const chunk = toUint8Array(data);
        if (!chunk.byteLength) return;
        await serialSendRawChunk(chunk);
      } catch (err) {
        activeSendError ||= err;
        throw err;
      } finally {
        activeDirectSendCount--;
        markSendDone();
      }
    },
    async send(data) {
      if (stopStarted || !currentSenderActive()) return;
      activeSendCount++;
      try {
        const chunk = toUint8Array(data);
        if (!chunk.byteLength) return;
        let offset = 0;
        const totalBytes = chunk.byteLength;
        while (offset < totalBytes) {
          const remainingBytes = totalBytes - offset;
          if (grain.isEmpty && remainingBytes >= packetCap) {
            const sendBytes = Math.min(packetCap, remainingBytes);
            const view = offset || sendBytes !== totalBytes ? chunk.subarray(offset, offset + sendBytes) : chunk;
            await serialSendRawChunk(view);
            offset += sendBytes;
            continue;
          }
          const copyBytes = Math.min(packetCap - grain.byteCount, totalBytes - offset);
          if (!copyBytes) {
            await flush();
            continue;
          }
          grain.absorb({ chunk: offset || copyBytes !== totalBytes ? chunk.subarray(offset, offset + copyBytes) : chunk });
          offset += copyBytes;
          generation++;
          if (grain.byteCount >= packetCap || packetCap - grain.byteCount < tailBytes) await flush();
          else scheduleFlush();
        }
      } catch (err) {
        activeSendError ||= err;
        throw err;
      } finally {
        activeSendCount--;
        markSendDone();
      }
    },
    flush,
    async stopAndFlush() {
      if (stopStarted) {
        await waitForActiveSends();
        while (directSendPromise) await directSendPromise;
        checkActiveSendError();
        await flush();
        return;
      }
      stopStarted = true;
      forceDrain = true;
      if (flushTimer) clearTimeout(flushTimer);
      flushTimer = null;
      await waitForActiveSends();
      while (directSendPromise) await directSendPromise;
      checkActiveSendError();
      await flush();
    },
  };
}

void concatByteChunks;
void effectiveByteLength;
