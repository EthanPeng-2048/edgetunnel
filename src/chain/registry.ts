/**
 * 链式代理注册表（DESIGN.md §4.4 可插拔：新增链式 = 新子类 + 此处注册）。
 *
 * 键 = proxyCtx.proxyType（原 forwardataTCP 的 ctxProxyType 分支）：
 * socks5 / http / https / turn / sstp。
 */
import { ChainRegistry } from './base';
import { Socks5Provider } from './socks5';
import { HttpProvider } from './http';
import { HttpsProvider } from './https';
import { TurnProvider } from './turn';
import { SstpProvider } from './sstp';

export const chainRegistry = new ChainRegistry()
  .register(new Socks5Provider())
  .register(new HttpProvider())
  .register(new HttpsProvider())
  .register(new TurnProvider())
  .register(new SstpProvider());

export { ChainProvider, ChainRegistry } from './base';
export type { ChainDialParams, ChainDialResult, ChainProxyEndpoint, ChainSocket } from './base';
