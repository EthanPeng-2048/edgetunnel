/**
 * loadConfig（原 _worker.js L5713-5962，行为等价移植 + 插件钩子接线）。
 *
 * 职责：读 KV config.json → 中文键迁移 → 补齐缺省 → 计算 fullNodePath/LINK/TOKEN
 * → 加载 tg.json / cf.json → 依次执行插件 onConfigLoad → 返回**新对象**。
 *
 * 与原实现的差异（有意为之）：
 * 1. 不再写模块级 config_JSON —— 返回值由调用方持有（消除并发覆盖，见文件头警示）；
 * 2. socks5Whitelist 由参数传入（原为模块级全局 + env.GO2SOCKS5 合并，后者随 P4 入口接线）；
 * 3. 末尾新增插件 onConfigLoad 钩子（DESIGN.md §4.5）。
 */
import type { RequestContext } from '../context';
import type { Env } from '../env';
import { migrateConfigKeysDeep, CONFIG_KEY_CN_TO_EN } from './key-migration';
import { createDefaultConfig, PLACEHOLDER, DEFAULT_SOCKS5_WHITELIST, type Config } from './schema';
import { getTransportConfig, getTransportPathValue } from './transport';
import { BRAND_PROXYIP } from '../services/brand';
import { md5Md5 } from '../services/md5';
import { maskSensitive } from '../utils/mask';
import { ensureArray } from '../utils/array';
import { getCloudflareUsage } from '../services/cf-usage';
import { getPlugins } from '../plugins/registry';
import type { Plugin } from '../plugins/base';

export interface LoadConfigOptions {
  /** 重置为默认值（原 resetConfig；admin/init 路由使用） */
  reset?: boolean;
  /** SOCKS5 白名单（原模块级 socks5Whitelist；缺省用 DEFAULT_SOCKS5_WHITELIST） */
  socks5Whitelist?: string[];
  /** 插件列表；缺省用全局注册表 */
  plugins?: readonly Plugin[];
}

export async function loadConfig(rctx: RequestContext, options: LoadConfigOptions = {}): Promise<Config> {
  const env: Env = rctx.env;
  const hostname = rctx.host;
  const userID = rctx.userId;
  const ua = rctx.ua;
  const initStartTime = performance.now();
  const socks5Whitelist = options.socks5Whitelist ?? DEFAULT_SOCKS5_WHITELIST;

  const defaultConfig = await createDefaultConfig(hostname, userID, ua, socks5Whitelist);

  let config: Config;
  try {
    const configJSON = await env.KV?.get('config.json');
    if (!configJSON || options.reset === true) {
      await env.KV?.put('config.json', JSON.stringify(defaultConfig, null, 2));
      config = defaultConfig;
    } else {
      config = migrateConfigKeysDeep(JSON.parse(configJSON), CONFIG_KEY_CN_TO_EN) as Config;
    }
  } catch (error) {
    console.error(`读取config_JSON出错: ${(error as Error).message}`);
    config = defaultConfig;
  }

  // —— 缺省补齐（原 L5831-5848）——
  if (!config.subConverterConfig.SUBLIST) config.subConverterConfig.SUBLIST = false;
  if (!config.subConverterConfig.UDP) config.subConverterConfig.UDP = false;
  if (!config.subConverterConfig.XUDP) config.subConverterConfig.XUDP = false;
  if (!config.subConverterConfig.TLS13) config.subConverterConfig.TLS13 = false;
  if (!config.subConverterConfig.APPEND_TYPE) config.subConverterConfig.APPEND_TYPE = false;
  if (!config.subConverterConfig.SORT) config.subConverterConfig.SORT = false;
  if (typeof config.subConverterConfig.EXPAND !== 'boolean') config.subConverterConfig.EXPAND = true;
  if (!config.gRPCUserAgent) config.gRPCUserAgent = ua;
  config.HOST = hostname;
  if (!config.HOSTS) config.HOSTS = [hostname];
  if (env.HOST) config.HOSTS = ensureArray(String(env.HOST)).map((h) => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0]!.split(':')[0]!);
  config.UUID = userID;
  if (!config.randomPath) config.randomPath = false;
  if (!config.enable0RTT) config.enable0RTT = false;

  if (env.PATH) config.PATH = String(env.PATH).startsWith('/') ? String(env.PATH) : '/' + String(env.PATH);
  else if (!config.PATH) config.PATH = '/';
  if (!config.ALPN) config.ALPN = '';

  if (!config.grpcMode) config.grpcMode = 'gun';
  if (!config.SS) config.SS = { encryptionMethod: 'aes-128-gcm', TLS: false };

  // —— pathTemplates 兜底（原 L5853-5880）——
  if (!config.proxy.pathTemplates?.[BRAND_PROXYIP]) {
    config.proxy.pathTemplates = {
      [BRAND_PROXYIP]: 'proxyip=' + PLACEHOLDER,
      SOCKS5: { global: 'socks5://' + PLACEHOLDER, standard: 'socks5=' + PLACEHOLDER },
      HTTP: { global: 'http://' + PLACEHOLDER, standard: 'http=' + PLACEHOLDER },
      HTTPS: { global: 'https://' + PLACEHOLDER, standard: 'https=' + PLACEHOLDER },
      TURN: { global: 'turn://' + PLACEHOLDER, standard: 'turn=' + PLACEHOLDER },
      SSTP: { global: 'sstp://' + PLACEHOLDER, standard: 'sstp=' + PLACEHOLDER },
    };
  }
  if (!config.proxy.pathTemplates.HTTPS) config.proxy.pathTemplates.HTTPS = { global: 'https://' + PLACEHOLDER, standard: 'https=' + PLACEHOLDER };
  if (!config.proxy.pathTemplates.TURN) config.proxy.pathTemplates.TURN = { global: 'turn://' + PLACEHOLDER, standard: 'turn=' + PLACEHOLDER };
  if (!config.proxy.pathTemplates.SSTP) config.proxy.pathTemplates.SSTP = { global: 'sstp://' + PLACEHOLDER, standard: 'sstp=' + PLACEHOLDER };

  // —— 反代路径参数与 fullNodePath（原 L5882-5900）——
  const proxyConfig = config.proxy.pathTemplates[config.proxy.SOCKS5.enabled?.toUpperCase() ?? ''];

  let pathProxyParams = '';
  if (proxyConfig && typeof proxyConfig !== 'string' && config.proxy.SOCKS5.account) {
    pathProxyParams = (config.proxy.SOCKS5.global ? proxyConfig.global : proxyConfig.standard).replace(PLACEHOLDER, config.proxy.SOCKS5.account);
  } else if (config.proxy[BRAND_PROXYIP] !== 'auto') {
    pathProxyParams = config.proxy.pathTemplates[BRAND_PROXYIP]!.replace(PLACEHOLDER, config.proxy[BRAND_PROXYIP]);
  }

  let proxySearchParams = '';
  if (pathProxyParams.includes('?')) {
    const [proxyPathPart = '', proxyQueryPart = ''] = pathProxyParams.split('?');
    pathProxyParams = proxyPathPart;
    proxySearchParams = proxyQueryPart;
  }

  config.PATH = config.PATH.replace(pathProxyParams, '').replace('//', '/');
  const normalizedPath = config.PATH === '/' ? '' : config.PATH.replace(/\/+(?=\?|$)/, '').replace(/\/+$/, '');
  const [pathPart, ...queryArray] = normalizedPath.split('?');
  const queryPart = queryArray.length ? '?' + queryArray.join('?') : '';
  const finalQueryPart = proxySearchParams ? (queryPart ? queryPart + '&' + proxySearchParams : '?' + proxySearchParams) : queryPart;
  config.fullNodePath =
    (pathPart || '/') +
    (pathPart && pathProxyParams ? '/' : '') +
    pathProxyParams +
    finalQueryPart +
    (config.enable0RTT ? (finalQueryPart ? '&' : '?') + 'ed=2560' : '');

  // —— TLS/ECH 参数（原 L5902-5907）——
  if (!config.tlsFragment && config.tlsFragment !== null) config.tlsFragment = null;
  const tlsFragmentParams =
    config.tlsFragment == 'Shadowrocket'
      ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}`
      : config.tlsFragment == 'Happ'
        ? `&fragment=${encodeURIComponent('3,1,tlshello')}`
        : '';
  if (!config.Fingerprint) config.Fingerprint = 'chrome';
  if (!config.ECH) config.ECH = false;
  if (!config.ECHConfig) config.ECHConfig = { DNS: 'https://dns.alidns.com/dns-query', SNI: 'cloudflare-ech.com' };
  const echLinkParams = config.ECH ? `&ech=${encodeURIComponent((config.ECHConfig.SNI ? config.ECHConfig.SNI + '+' : '') + config.ECHConfig.DNS)}` : '';

  // —— LINK 计算（原 L5908-5913）——
  const { type: transport, pathFieldName, hostFieldName } = getTransportConfig(config);
  const transportPathValue = getTransportPathValue(config, config.fullNodePath);
  config.LINK =
    config.protocolType === 'ss'
      ? `${config.protocolType}://${btoa(config.SS.encryptionMethod + ':' + userID)}@${hostname}:${
          config.SS.TLS ? '443' : '80'
        }?plugin=v2${encodeURIComponent(
          `ray-plugin;mode=websocket;host=${hostname};path=${
            (config.fullNodePath.includes('?')
              ? config.fullNodePath.replace('?', '?enc=' + config.SS.encryptionMethod + '&')
              : config.fullNodePath + '?enc=' + config.SS.encryptionMethod) + (config.SS.TLS ? ';tls' : '')
          };mux=0`,
        ) + echLinkParams}#${encodeURIComponent(config.bestSubGen.SUBNAME)}`
      : `${config.protocolType}://${userID}@${hostname}:443?security=tls&type=${transport + echLinkParams}&${hostFieldName}=${hostname}&fp=${config.Fingerprint}&sni=${hostname}&${pathFieldName}=${encodeURIComponent(
          transportPathValue,
        ) + tlsFragmentParams}&encryption=none#${encodeURIComponent(config.bestSubGen.SUBNAME)}`;
  config.bestSubGen.TOKEN = md5Md5(hostname + userID);

  // —— TG 段（原 L5915-5928）——
  const defaultTgJson = { BotToken: null, ChatID: null };
  config.TG = { enabled: config.TG?.enabled ? config.TG.enabled : false, ...defaultTgJson };
  try {
    const TG_TXT = await env.KV?.get('tg.json');
    if (!TG_TXT) {
      await env.KV?.put('tg.json', JSON.stringify(defaultTgJson, null, 2));
    } else {
      const TG_JSON = JSON.parse(TG_TXT) as { ChatID?: string | null; BotToken?: string | null };
      config.TG.ChatID = TG_JSON.ChatID ? TG_JSON.ChatID : null;
      config.TG.BotToken = TG_JSON.BotToken ? maskSensitive(TG_JSON.BotToken) : null;
    }
  } catch (error) {
    console.error(`读取tg.json出错: ${(error as Error).message}`);
  }

  // —— CF 段（原 L5930-5958）——
  const defaultCfJson = { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null, UsageAPI: null };
  config.CF = { ...defaultCfJson, Usage: { success: false, pages: 0, workers: 0, total: 0, max: 100000 } };
  try {
    const CF_TXT = await env.KV?.get('cf.json');
    if (!CF_TXT) {
      await env.KV?.put('cf.json', JSON.stringify(defaultCfJson, null, 2));
    } else {
      const CF_JSON = JSON.parse(CF_TXT) as typeof defaultCfJson;
      if (CF_JSON.UsageAPI) {
        try {
          const response = await fetch(CF_JSON.UsageAPI);
          config.CF.Usage = (await response.json()) as Config['CF']['Usage'];
        } catch (err) {
          console.error(`请求 CF_JSON.UsageAPI 失败: ${(err as Error).message}`);
        }
      } else {
        config.CF.Email = CF_JSON.Email ? CF_JSON.Email : null;
        config.CF.GlobalAPIKey = CF_JSON.GlobalAPIKey ? maskSensitive(CF_JSON.GlobalAPIKey) : null;
        config.CF.AccountID = CF_JSON.AccountID ? maskSensitive(CF_JSON.AccountID) : null;
        config.CF.APIToken = CF_JSON.APIToken ? maskSensitive(CF_JSON.APIToken) : null;
        config.CF.UsageAPI = null;
        config.CF.Usage = await getCloudflareUsage(CF_JSON.Email, CF_JSON.GlobalAPIKey, CF_JSON.AccountID, CF_JSON.APIToken);
      }
    }
  } catch (error) {
    console.error(`读取cf.json出错: ${(error as Error).message}`);
  }

  config.loadTime = (performance.now() - initStartTime).toFixed(2) + 'ms';

  // —— 插件钩子（DESIGN.md §4.5，原实现无此步）——
  for (const plugin of options.plugins ?? getPlugins()) {
    if (plugin.onConfigLoad) config = await plugin.onConfigLoad(config, rctx);
  }

  return config;
}
