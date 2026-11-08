/**
 * 插件基类（DESIGN.md §4.5）。
 *
 * 订阅 / 优选 / 管理页 UI / 伪装页等均为其子类，经 registerPlugin 注册；
 * loadConfig 执行 onConfigLoad，Router 执行 onRoute，
 * Forwarder 在拨号前执行 onBeforeDial。
 */
import type { RequestContext } from '../context';
import type { Config } from '../config/schema';

/** 出站拨号计划（DESIGN.md §4.5；forwarder 在拨号前交给插件改写） */
export interface DialPlan {
  host: string;
  port: number;
  userId?: string;
  /** 链式代理类型（null = 直连 / ProxyIP 反代） */
  proxyType?: string | null;
  /** 链式代理参数（socks5 账号等） */
  proxyParams?: { hostname?: string; port?: number; username?: string; password?: string };
}

export abstract class Plugin {
  abstract readonly name: string;

  /**
   * 兜底插件（FakePage）：不参与主路由链，Router 在核心路由与普通插件
   * 全部未命中后单独调用（对应原 else-if 链落出后的 L526+ 伪装页）。
   */
  readonly fallback?: boolean;

  /** 挂 HTTP 路由；返回 null 表示不处理，交还 Router 继续分发 */
  onRoute?(rctx: RequestContext): Promise<Response | null>;

  /** loadConfig 完成后变换配置（订阅热补丁、优选注入等） */
  onConfigLoad?(config: Config, rctx: RequestContext): Promise<Config>;

  /** 实际拨号前改写出站计划；返回新计划或原样（DESIGN.md §4.5） */
  onBeforeDial?(plan: DialPlan, rctx: RequestContext): Promise<DialPlan>;
}
