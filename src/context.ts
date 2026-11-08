/**
 * 每请求上下文（DESIGN.md §4.1）—— 消除模块级可变全局。
 *
 * 现状 _worker.js 的 config_JSON / debugLogging / socks5Whitelist 等是模块级 let，
 * 同 isolate 并发请求互相覆盖。重构后一律挂在本对象。
 *
 * 管理密码链 / 加密密钥 / userId 派生 / hosts 解析与原 fetch 入口（L50-71）逐行等价，
 * 其中 MD5MD5 已改为同步纯 TS（services/md5），构造器保持同步。
 */
import type { Env } from './env';
import { md5Md5 } from './services/md5';
import { getIdentity } from './services/identity';
import { ensureArray } from './utils/array';
import { BRAND_PROXYIP, BRAND_OWNER } from './services/brand';
import { DEFAULT_SOCKS5_WHITELIST } from './config/schema';

/** ASN / 组织关键词 → ISP 代码（原 detectISP；cmcc 触发拨号降并发；订阅 cnIspCode 也用它） */
export function detectISPFromRequest(request: Request): string {
  const cf = (request as Request & { cf?: { country?: string; asOrganization?: string; asn?: number | string } }).cf;
  const ASN_ISP_MAP: Record<string, string> = {
    '4134': 'ct', '4809': 'ct', '4811': 'ct', '4812': 'ct', '4815': 'ct',
    '4837': 'cu', '4814': 'cu', '9929': 'cu', '17623': 'cu', '17816': 'cu',
    '9808': 'cmcc', '24400': 'cmcc', '56040': 'cmcc', '56041': 'cmcc', '56044': 'cmcc',
  };
  const ISP_KEYWORD_MAP: Array<{ code: string; pattern: RegExp }> = [
    { code: 'ct', pattern: /chinanet|chinatelecom|china telecom|cn2|shtel/ },
    { code: 'cmcc', pattern: /cmi|cmnet|chinamobile|china mobile|cmcc|mobile communications/ },
    { code: 'cu', pattern: /china169|china unicom|chinaunicom|cucc|cncgroup|cuii|netcom/ },
  ];
  if (String(cf?.country || '').toLowerCase() !== 'cn') return 'cf';
  const orgName = String(cf?.asOrganization || '').toLowerCase();
  const ispHit = ISP_KEYWORD_MAP.find(({ pattern }) => pattern.test(orgName))?.code;
  return ispHit || ASN_ISP_MAP[String(cf?.asn || '')] || 'cf';
}

/** SOCKS5 白名单：默认池 ∪ env.GO2SOCKS5（原 L72-75；结果按 env 指纹缓存） */
let cachedSocks5Whitelist: { envFingerprint: string; list: string[] } | null = null;
function resolveSocks5Whitelist(env: Env): string[] {
  const fingerprint = String(env.GO2SOCKS5 ?? '');
  if (cachedSocks5Whitelist && cachedSocks5Whitelist.envFingerprint === fingerprint) {
    return cachedSocks5Whitelist.list;
  }
  let list = [...DEFAULT_SOCKS5_WHITELIST];
  if (env.GO2SOCKS5) list = [...new Set(list.concat(ensureArray(String(env.GO2SOCKS5))))];
  cachedSocks5Whitelist = { envFingerprint: fingerprint, list };
  return list;
}

/** v4 UUID 校验（原 fetch 入口 uuidRegex；logout 路由也复用） */
export const UUID_REGEX = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;

/** 原 encryptionSecret 兜底值（env.KEY 未设置时）—— 文本本身是兼容契约，勿改 */
export const DEFAULT_ENCRYPTION_SECRET = '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改';

/** 原 adminPassword 的 env 解码链（顺序即优先级，L50） */
const ADMIN_PASSWORD_KEYS = ['ADMIN', 'admin', 'PASSWORD', 'password', 'pswd', 'TOKEN', 'KEY', 'UUID', 'uuid'] as const;

/** 取链中第一个真值并字符串化（与原 `||` 链 + 隐式字符串拼接行为一致） */
function firstTruthyString(values: unknown[]): string | undefined {
  for (const v of values) {
    if (v) return String(v);
  }
  return undefined;
}

export class RequestContext {
  readonly requestId: string;
  readonly request: Request;
  readonly env: Env;
  readonly ctx: ExecutionContext;
  readonly url: URL;
  readonly ua: string;
  readonly clientIp: string;
  /** DEBUG 开关（env.DEBUG = 1/true），原模块级 debugLogging 的每请求化 */
  readonly debug: boolean;
  /** 管理密码（原 adminPassword env 链）；undefined = 未配置 → 走 noADMIN 兜底 */
  readonly adminPassword: string | undefined;
  /** 加密密钥（原 encryptionSecret：env.KEY || 默认常量） */
  readonly encryptionSecret: string;
  /** 用户 ID（env.UUID 合法则小写，否则 MD5MD5 派生 UUID）—— 兼容红线 #2 */
  readonly userId: string;
  /** HOST 列表（env.HOST 拆分或 url.hostname）与首项 */
  readonly hosts: string[];
  readonly host: string;
  /** 本机标识 [请求头名, 查询参数名]（xHTTP 首包识别用） */
  readonly identity: readonly [string, string];
  /** 每请求调优参数（原模块级 tcpConcurrentDial / proxyConcurrentDial / preloadRaceDial） */
  readonly dial: {
    tcpConcurrentDial: number;
    proxyConcurrentDial: number;
    preloadRaceDial: boolean;
  };
  /** CF 边缘元数据（colo / asn / asOrganization / country）—— 原 request.cf */
  readonly cf: { colo?: string; asn?: number | string; asOrganization?: string; country?: string } | undefined;
  /** 默认反代 IP（原 defaultProxyIP：env.PROXYIP 或 colo.品牌域名） */
  readonly defaultProxyIP: string;
  /** 默认反代兜底开关（env.PROXYIP 存在时为 false，原 defaultProxyFallback） */
  readonly defaultProxyFallback: boolean;
  /** SOCKS5 白名单（原模块级 socks5Whitelist + env.GO2SOCKS5 合并；启动期缓存） */
  socks5Whitelist: string[];

  constructor(request: Request, env: Env, ctx: ExecutionContext) {
    this.requestId = crypto.randomUUID().slice(0, 8);
    this.request = request;
    this.env = env;
    this.ctx = ctx;
    this.url = new URL(request.url);
    this.ua = request.headers.get('User-Agent') || 'null';
    this.debug = ['1', 'true'].includes(String(env.DEBUG ?? ''));
    this.clientIp =
      request.headers.get('CF-Connecting-IP') ||
      request.headers.get('X-Real-IP') ||
      request.headers.get('X-Forwarded-For') ||
      '未知IP';

    // —— 以下与原 fetch 入口 L50-71 逐行等价 ——
    this.adminPassword = firstTruthyString(ADMIN_PASSWORD_KEYS.map((k) => env[k]));
    const keyRaw = env.KEY;
    this.encryptionSecret = keyRaw ? String(keyRaw) : DEFAULT_ENCRYPTION_SECRET;
    // 模板拼接保留原 `adminPassword + encryptionSecret` 的 undefined → 'undefined' 强制转换语义
    const userIdMD5 = md5Md5(`${this.adminPassword}${this.encryptionSecret}`);
    const envUuid = firstTruthyString([env.UUID, env.uuid]);
    this.userId =
      envUuid && UUID_REGEX.test(envUuid)
        ? envUuid.toLowerCase()
        : [
            userIdMD5.slice(0, 8),
            userIdMD5.slice(8, 12),
            '4' + userIdMD5.slice(13, 16),
            '8' + userIdMD5.slice(17, 20),
            userIdMD5.slice(20),
          ].join('-');

    const hostRaw = env.HOST;
    this.hosts = hostRaw
      ? ensureArray(String(hostRaw)).map((h) => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0]!.split(':')[0]!)
      : [this.url.hostname];
    this.host = this.hosts[0] ?? this.url.hostname;
    this.identity = getIdentity(this.userId);

    // —— 调优参数（原 fetch L60-63，每请求从 env 覆写 —— 消除模块级 let）——
    this.dial = {
      tcpConcurrentDial: Math.max(1, Number(env.TCP_CONCURRENT_DIAL) || 2),
      proxyConcurrentDial: Math.max(1, Number(env.PROXY_CONCURRENT_DIAL) || 1),
      preloadRaceDial: ['1', 'true'].includes(String(env.PRELOAD_RACE_DIAL ?? '')),
    };
    // CMCC ISP 降并发（原 L63：仅当未显式配置 TCP_CONCURRENT_DIAL）
    if (!env.TCP_CONCURRENT_DIAL && this.dial.tcpConcurrentDial !== 1 && detectISPFromRequest(request) === 'cmcc') {
      (this.dial as { tcpConcurrentDial: number }).tcpConcurrentDial = 1;
    }

    // —— CF 元数据与默认反代（原 L64-69）——
    this.cf = (request as Request & { cf?: RequestContext['cf'] }).cf;
    const colo = String(this.cf?.colo || '').toUpperCase();
    this.defaultProxyIP = `${colo}.${BRAND_PROXYIP}.${BRAND_OWNER}SsSs.nEt`.toLowerCase();
    if (env.PROXYIP) {
      const proxyIPs = ensureArray(String(env.PROXYIP));
      this.defaultProxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)] ?? this.defaultProxyIP;
      this.defaultProxyFallback = false;
    } else {
      this.defaultProxyFallback = true;
    }

    // —— SOCKS5 白名单（原 L23 + L72-75 模块级缓存 → 每请求合并结果）——
    this.socks5Whitelist = resolveSocks5Whitelist(env);
  }

  /**
   * 统一日志格式：[requestId][模块] 消息（DESIGN.md §4.7）。
   * 仅 debug 打开时输出（原 log() 语义）；错误路径用 console.error 直出。
   */
  log(module: string, ...args: unknown[]): void {
    if (this.debug) console.log(`[${this.requestId}][${module}]`, ...args);
  }

  /** 错误日志：始终输出（错误不可被 debug 开关吞掉） */
  error(module: string, ...args: unknown[]): void {
    console.error(`[${this.requestId}][${module}]`, ...args);
  }
}
