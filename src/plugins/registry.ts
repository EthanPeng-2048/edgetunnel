/**
 * 插件注册表（模块级启动期注册 —— 与被消除的「每请求可变全局」不同，
 * 这里在 Worker 启动后不再变化，属只读组件表）。
 */
import type { Plugin } from './base';

const plugins: Plugin[] = [];

export function registerPlugin(plugin: Plugin): void {
  plugins.push(plugin);
}

export function getPlugins(): readonly Plugin[] {
  return plugins;
}

/** 主路由链（fallback 插件除外）—— Router 在核心路由之前遍历 */
export function getRoutePlugins(): readonly Plugin[] {
  return plugins.filter((p) => !p.fallback);
}

/** 兜底插件（如 FakePagePlugin）—— Router 在全部未命中后遍历 */
export function getFallbackPlugins(): readonly Plugin[] {
  return plugins.filter((p) => p.fallback);
}
