/**
 * SOCKS5 链式代理（原 _worker.js socks5Connect，行为等价移植）。
 *
 * 握手序列：方法协商 → 可选用户名/密码认证 → CONNECT 请求 → 写首包。
 * 返回的 socket.writable / socket.readable 已解锁（原 writer/reader.releaseLock）。
 */
import { ChainProvider, type ChainDialParams, type ChainDialResult } from './base';
import { TunnelError } from '../errors';
import { effectiveByteLength, toUint8Array } from '../utils/bytes';

export class Socks5Provider extends ChainProvider {
  readonly name = 'socks5';

  async dial(params: ChainDialParams): Promise<ChainDialResult> {
    const { proxy, target, initialData, tcpConnect } = params;
    const { username, password, hostname, port } = proxy;
    const socket = tcpConnect({ hostname, port });
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    try {
      const authMethods = username && password ? new Uint8Array([0x05, 0x02, 0x00, 0x02]) : new Uint8Array([0x05, 0x01, 0x00]);
      await writer.write(authMethods);
      let response = await reader.read();
      if (response.done || !response.value || response.value.byteLength < 2) {
        throw new TunnelError('CHAIN_SOCKS5_HANDSHAKE', 'S5 method selection failed');
      }

      const selectedMethod = toUint8Array(response.value)[1]!;
      if (selectedMethod === 0x02) {
        if (!username || !password) throw new TunnelError('CHAIN_SOCKS5_AUTH', 'S5 requires authentication');
        const userBytes = new TextEncoder().encode(username);
        const passBytes = new TextEncoder().encode(password);
        const authPacket = new Uint8Array([0x01, userBytes.length, ...userBytes, passBytes.length, ...passBytes]);
        await writer.write(authPacket);
        response = await reader.read();
        if (response.done || !response.value || toUint8Array(response.value)[1] !== 0x00) {
          throw new TunnelError('CHAIN_SOCKS5_AUTH', 'S5 authentication failed');
        }
      } else if (selectedMethod !== 0x00) {
        throw new TunnelError('CHAIN_SOCKS5_HANDSHAKE', `S5 unsupported auth method: ${selectedMethod}`);
      }

      const hostBytes = new TextEncoder().encode(target.host);
      const connectPacket = new Uint8Array([0x05, 0x01, 0x00, 0x03, hostBytes.length, ...hostBytes, target.port >> 8, target.port & 0xff]);
      await writer.write(connectPacket);
      response = await reader.read();
      if (response.done || !response.value || toUint8Array(response.value)[1] !== 0x00) {
        throw new TunnelError('CHAIN_SOCKS5_CONNECT', 'S5 connection failed');
      }

      if (effectiveByteLength(initialData) > 0) await writer.write(toUint8Array(initialData));
      writer.releaseLock();
      reader.releaseLock();
      return { socket };
    } catch (error) {
      try {
        writer.releaseLock();
      } catch {
        /* ignore */
      }
      try {
        reader.releaseLock();
      } catch {
        /* ignore */
      }
      try {
        socket.close?.();
      } catch {
        /* ignore */
      }
      throw error;
    }
  }
}
