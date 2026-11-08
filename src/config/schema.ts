/**
 * 配置 Schema（DESIGN.md §6）。
 *
 * Config 是 loadConfig 的返回类型：英文键（兼容红线 #1 的对外中文键
 * 由 key-migration.ts 在边界转换）。字段与原 defaultConfigJson 逐项对应。
 */
import { BRAND_OWNER, BRAND_PROXYIP } from '../services/brand';
import { md5Md5 } from '../services/md5';

export interface Socks5Section {
  enabled: string | null;
  global: boolean;
  account: string;
  whitelist: string[];
}

export interface PathTemplates {
  [BRAND_PROXYIP]: string;
  SOCKS5: { global: string; standard: string };
  HTTP: { global: string; standard: string };
  HTTPS: { global: string; standard: string };
  TURN: { global: string; standard: string };
  SSTP: { global: string; standard: string };
  /** 动态键（SOCKS5.enabled 大写化后查表，原实现用任意字符串索引） */
  [key: string]: string | { global: string; standard: string };
}

export interface ProxySection {
  [BRAND_PROXYIP]: string;
  SOCKS5: Socks5Section;
  pathTemplates: PathTemplates;
}

export interface BestSubGenSection {
  local: boolean;
  localIPPool: { randomIP: boolean; randomCount: number; fixedPort: number };
  SUB: string | null;
  SUBNAME: string;
  SUBUpdateTime: number;
  TOKEN: string;
}

export interface SubConverterSection {
  SUBAPI: string;
  SUBCONFIG: string;
  SUBEMOJI: boolean;
  SUBLIST: boolean;
  UDP: boolean;
  XUDP: boolean;
  TLS13: boolean;
  APPEND_TYPE: boolean;
  SORT: boolean;
  EXPAND: boolean;
}

export interface TgSection {
  enabled: boolean;
  BotToken: string | null;
  ChatID: string | null;
}

export interface CfUsage {
  success: boolean;
  pages: number;
  workers: number;
  total: number;
  max: number;
}

export interface CfSection {
  Email: string | null;
  GlobalAPIKey: string | null;
  AccountID: string | null;
  APIToken: string | null;
  UsageAPI: string | null;
  Usage: CfUsage;
}

export interface Config {
  TIME: string;
  HOST: string;
  HOSTS: string[];
  UUID: string;
  PATH: string;
  ALPN: string;
  protocolType: string;
  transport: string;
  grpcMode: string;
  gRPCUserAgent: string;
  skipCertVerify: boolean;
  enable0RTT: boolean;
  tlsFragment: string | null;
  randomPath: boolean;
  ECH: boolean;
  ECHConfig: { DNS: string; SNI: string };
  SS: { encryptionMethod: string; TLS: boolean };
  Fingerprint: string;
  bestSubGen: BestSubGenSection;
  subConverterConfig: SubConverterSection;
  proxy: ProxySection;
  TG: TgSection;
  CF: CfSection;
  /** loadConfig 计算字段 */
  fullNodePath: string;
  LINK: string;
  loadTime?: string;
  /** admin/init 重置后附加的提示字段（原 L234） */
  init?: string;
}

/** 原 loadConfig 内联常量 */
const ALI_DOH = 'https://dns.alidns.com/dns-query';
const ECH_SNI = 'cloudflare-ech.com';
export const PLACEHOLDER = '{{IP:PORT}}';

/**
 * 构建默认配置（原 defaultConfigJson）。
 * 异步仅因 bestSubGen.TOKEN = MD5MD5(hostname + userID)。
 */
export async function createDefaultConfig(
  host: string,
  userID: string,
  ua: string,
  socks5Whitelist: string[],
): Promise<Config> {
  return {
    TIME: new Date().toISOString(),
    HOST: host,
    HOSTS: [host],
    UUID: userID,
    PATH: '/',
    ALPN: '',
    protocolType: 'vless',
    transport: 'ws',
    grpcMode: 'gun',
    gRPCUserAgent: ua,
    skipCertVerify: false,
    enable0RTT: false,
    tlsFragment: null,
    randomPath: false,
    ECH: false,
    ECHConfig: { DNS: ALI_DOH, SNI: ECH_SNI },
    SS: { encryptionMethod: 'aes-128-gcm', TLS: true },
    Fingerprint: 'chrome',
    bestSubGen: {
      local: true,
      localIPPool: { randomIP: true, randomCount: 16, fixedPort: -1 },
      SUB: null,
      SUBNAME: 'xtunnel',
      SUBUpdateTime: 3,
      TOKEN: await md5Md5(host + userID),
    },
    subConverterConfig: {
      SUBAPI: `https://SUBAPI.${BRAND_OWNER}ssss.net`,
      SUBCONFIG: `https://raw.githubusercontent.com/${BRAND_OWNER}/ACL4SSR/refs/heads/main/Clash/config/ACL4SSR_Online_Mini_MultiMode_CF.ini`,
      SUBEMOJI: false,
      SUBLIST: false,
      UDP: false,
      XUDP: false,
      TLS13: false,
      APPEND_TYPE: false,
      SORT: false,
      EXPAND: true,
    },
    proxy: {
      [BRAND_PROXYIP]: 'auto',
      SOCKS5: { enabled: null, global: false, account: '', whitelist: socks5Whitelist },
      pathTemplates: {
        [BRAND_PROXYIP]: 'proxyip=' + PLACEHOLDER,
        SOCKS5: { global: 'socks5://' + PLACEHOLDER, standard: 'socks5=' + PLACEHOLDER },
        HTTP: { global: 'http://' + PLACEHOLDER, standard: 'http=' + PLACEHOLDER },
        HTTPS: { global: 'https://' + PLACEHOLDER, standard: 'https=' + PLACEHOLDER },
        TURN: { global: 'turn://' + PLACEHOLDER, standard: 'turn=' + PLACEHOLDER },
        SSTP: { global: 'sstp://' + PLACEHOLDER, standard: 'sstp=' + PLACEHOLDER },
      },
    },
    TG: { enabled: false, BotToken: null, ChatID: null },
    CF: {
      Email: null,
      GlobalAPIKey: null,
      AccountID: null,
      APIToken: null,
      UsageAPI: null,
      Usage: { success: false, pages: 0, workers: 0, total: 0, max: 100000 },
    },
    fullNodePath: '/',
    LINK: '',
  };
}

/** 原 loadConfig 使用的默认 SOCKS5 白名单（模块级 socks5Whitelist 初值） */
export const DEFAULT_SOCKS5_WHITELIST = [
  '*tapecontent.net',
  '*cloudatacdn.com',
  '*loadshare.org',
  '*cdn-centaurus.com',
  'scholar.google.com',
];
