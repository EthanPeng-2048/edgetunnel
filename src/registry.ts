/**
 * 通用组件注册表（DESIGN.md §4.6）。
 *
 * 传输层 / 协议层 / 链式代理 / 插件共用：
 * 按名注册与查找；传输与协议的选择不用 get()，而用 pickBest() 评分。
 */
import { TunnelError } from './errors';

export interface Named {
  readonly name: string;
}

export class Registry<T extends Named> {
  private readonly items = new Map<string, T>();

  register(item: T): this {
    if (this.items.has(item.name)) {
      throw new TunnelError('REGISTRY_DUPLICATE', `组件重名注册: ${item.name}`);
    }
    this.items.set(item.name, item);
    return this;
  }

  get(name: string): T | undefined {
    return this.items.get(name);
  }

  list(): T[] {
    return [...this.items.values()];
  }

  get size(): number {
    return this.items.size;
  }
}

/**
 * 评分择优（DESIGN.md §4.2：传输选择、协议嗅探共用）。
 * 遍历顺序即注册顺序；同分保留先注册者（严格大于才替换）。
 * 全部 0 分返回 undefined。
 */
export function pickBest<T>(items: readonly T[], score: (item: T) => number): T | undefined {
  let best: T | undefined;
  let bestScore = 0;
  for (const item of items) {
    const s = score(item);
    if (s > bestScore) {
      best = item;
      bestScore = s;
    }
  }
  return best;
}
