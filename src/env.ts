/**
 * 环境绑定与变量类型（DESIGN.md §4.1）。
 *
 * KV 用最小接口而非 workers-types 的 KVNamespace，便于测试注入 Map 模拟。
 * 索引签名兜底 worker 的自由变量（ADMIN / KEY / UUID / DEBUG / HOST / PATH ...）。
 */
export interface KVLike {
  get(key: string): Promise<string | null>;
  put(key: string, value: string): Promise<void>;
}

export interface Env {
  /** Static Assets 绑定（assets/pages/*.html），见 DESIGN.md §7 */
  ASSETS?: Fetcher;
  KV?: KVLike;
  [key: string]: unknown;
}
