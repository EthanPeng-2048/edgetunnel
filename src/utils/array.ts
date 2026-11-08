/**
 * 数组工具（原 _worker.js 章节 7 的纯函数）。
 */

/**
 * 把逗号/引号/换行分隔的字符串拆成数组（原 ensureArray）。
 * 原实现为 async 但无任何 await，这里改为同步；移植调用方时顺手去掉 await。
 *
 * 规则：`[\t"'\r\n]+` 折叠为 `,`，连续逗号合并，掐头去尾逗号后按 `,` 切分。
 * 注意：空输入返回 `['']`（与原实现一致，保留行为等价）。
 */
export function ensureArray(content: string): string[] {
  let replaced = content.replace(/[\t"'\r\n]+/g, ',').replace(/,+/g, ',');
  if (replaced.charAt(0) === ',') replaced = replaced.slice(1);
  if (replaced.charAt(replaced.length - 1) === ',') replaced = replaced.slice(0, replaced.length - 1);
  return replaced.split(',');
}

/** 单值/数组归一化为数组；null/undefined → []（原「数组化」箭头函数） */
export function asArray<T>(value: T | T[] | null | undefined): T[] {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}
