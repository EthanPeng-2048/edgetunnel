/**
 * 品牌常量（原 _worker.js 章节 1）。
 *
 * 上游用运行时拼接（Proxy.name / String.fromCharCode / 数字反转）绕过静态检索；
 * 下游 TS 编译产物自带混淆，直接写字面量。值与原运行结果完全一致（兼容红线 #4）。
 */

export const BRAND_PROXYIP = 'PROXYIP'; // 原 (Proxy.name + 'IP').toUpperCase()
export const BRAND_OWNER = 'cmliu'; // 原 String.fromCharCode(67,109) + URL.name[2] + 'i' + URL.name[0]
export const BRAND_TP1_ID = '090227'; // 原 String(2407 * 300 - 10) 反转
export const CLUSTER_SUB_UA = `v2rayN/edgetunnel (https://github.com/${BRAND_OWNER}/edgetunnel)`;

/** 版本号：原 Version 字符串 → EDT_VERSION 数字（去非数字拼接） */
export const VERSION = '2026-10-08 22:23:27';
export const EDT_VERSION = Number(VERSION.replace(/\D+/g, ''));
