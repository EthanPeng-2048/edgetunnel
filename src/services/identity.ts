/**
 * 本机标识派生（原 _worker.js getIdentity）。
 *
 * 由 userID（UUID）切片出请求头名与查询参数名：
 *   header = uuid[1..7)，key = '_' + uuid[25..31)
 * xHTTP 用它们做首包识别（命中信号），行为必须与原实现一致。
 */
export function getIdentity(userId: string): [header: string, key: string] {
  return [userId.slice(1, 7), '_' + userId.slice(25, 31)];
}
