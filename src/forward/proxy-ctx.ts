/**
 * proxyCtx 构建（原 _worker.js getProxyParams，行为等价移植）。
 *
 * 从 URL 查询参数 / 路径段解析链式代理与 ProxyIP 反代参数，
 * 产出 forwarder 使用的 ProxyContext。
 *
 * P5 范围：查询参数 / 路径段 / trojan= 反代地址。
 * P7 补：/video/<b64> 链式代理路径（base64SecretDecode，原 L6308-6331）。
 */
import type { RequestContext } from '../context';
import { TunnelError } from '../errors';
import { base64SecretDecode } from '../services/base64-secret';

export type ChainProxyType = 'socks5' | 'http' | 'https' | 'turn' | 'sstp';

export interface ParsedProxyAddress {
  username?: string;
  password?: string;
  hostname: string;
  port: number;
}

export interface ProxyContext {
  trojanProxyAddr: { hostname: string; port: number } | null;
  proxyIP: string;
  proxyType: ChainProxyType | null;
  proxyAccount: string;
  proxyGlobal: boolean;
  proxyParams: ParsedProxyAddress;
  proxyFallback: boolean;
}

const CHAIN_PROXY_DEFAULT_PORT: Record<string, number> = { socks5: 1080, http: 80, https: 443, turn: 3478, sstp: 443 };

export function getProxyDefaultPort(type: string | null | undefined): number {
  return CHAIN_PROXY_DEFAULT_PORT[String(type || '').toLowerCase()] || 80;
}

const SOCKS5_ACCOUNT_B64_RE = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
const IPV6_BRACKET_RE = /^\[.*\]$/;

/** 解析 socks5/http(s)/turn/sstp 账号串（原 getSocks5Account） */
export function getSocks5Account(address: string, defaultPort = 80): ParsedProxyAddress {
  let addr = String(address || '')
    .trim()
    .replace(/^(socks5|http|https|turn|sstp):\/\//i, '')
    .split('#')[0]!
    .trim();
  const firstAt = addr.lastIndexOf('@');
  if (firstAt !== -1) {
    let auth = addr.slice(0, firstAt).replaceAll('%3D', '=');
    if (!auth.includes(':') && SOCKS5_ACCOUNT_B64_RE.test(auth)) auth = atob(auth);
    addr = `${auth}@${addr.slice(firstAt + 1)}`;
  }

  const atIndex = addr.lastIndexOf('@');
  const hostPart = (atIndex === -1 ? addr : addr.slice(atIndex + 1)).split('/')[0]!;
  const authPart = atIndex === -1 ? '' : addr.slice(0, atIndex);
  const [username, password] = authPart ? authPart.split(':') : [];
  if (authPart && !password) throw new TunnelError('CHAIN_SOCKS5_ACCOUNT', '无效的 SOCKS 地址格式：认证部分必须是 "username:password" 的形式');

  let hostname = hostPart;
  let port = defaultPort;
  if (hostPart.includes(']:')) {
    const [ipv6Host, ipv6Port = ''] = hostPart.split(']:');
    hostname = ipv6Host + ']';
    port = Number(ipv6Port.replace(/[^\d]/g, ''));
  } else if (!hostPart.startsWith('[')) {
    const parts = hostPart.split(':');
    if (parts.length === 2) {
      hostname = parts[0]!;
      port = Number(parts[1]!.replace(/[^\d]/g, ''));
    }
  }

  if (Number.isNaN(port)) throw new TunnelError('CHAIN_SOCKS5_ACCOUNT', '无效的 SOCKS 地址格式：端口号必须是数字');
  if (hostname.includes(':') && !IPV6_BRACKET_RE.test(hostname)) {
    throw new TunnelError('CHAIN_SOCKS5_ACCOUNT', '无效的 SOCKS 地址格式：IPv6 地址必须用方括号括起来，如 [2001:db8::1]');
  }
  return { username, password, hostname, port };
}

/** 解析木马反代 host:port（原 parseTrojanProxyAddr） */
export function parseTrojanProxyAddr(address: string): { hostname: string; port: number } {
  const raw = String(address || '').trim();
  if (!raw || raw.includes('/') || raw.includes('@') || raw.includes('://')) {
    throw new TunnelError('CHAIN_TROJAN_ADDR', '木马反代仅支持 host:port');
  }
  let hostname = '';
  let portText = '';
  if (raw.startsWith('[')) {
    const match = raw.match(/^(\[[^\]]+\]):(\d+)$/);
    if (!match) throw new TunnelError('CHAIN_TROJAN_ADDR', '无效的 IPv6 木马反代地址');
    hostname = match[1]!;
    portText = match[2]!;
  } else {
    const parts = raw.split(':');
    if (parts.length !== 2) throw new TunnelError('CHAIN_TROJAN_ADDR', '木马反代仅支持 host:port');
    hostname = parts[0]!;
    portText = parts[1]!;
  }
  const port = Number(portText);
  if (!hostname || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new TunnelError('CHAIN_TROJAN_ADDR', '无效的木马反代端口');
  }
  return { hostname, port };
}

function extractPathValue(value: string): string {
  if (!value.includes('://')) {
    const slashIndex = value.indexOf('/');
    return slashIndex > 0 ? value.slice(0, slashIndex) : value;
  }
  const protocolSplit = value.split('://');
  if (protocolSplit.length !== 2) return value;
  const slashIndex = protocolSplit[1]!.indexOf('/');
  return slashIndex > 0 ? `${protocolSplit[0]}://${protocolSplit[1]!.slice(0, slashIndex)}` : value;
}

/**
 * 从 URL / env 构建 ProxyContext（原 getProxyParams）。
 * defaultProxyIP / defaultProxyFallback 由入口从 env.PROXYIP / request.cf.colo 计算。
 */
export function buildProxyContext(
  rctx: RequestContext,
  url: URL,
  defaultProxyIP = '',
  defaultProxyFallback = true,
): ProxyContext {
  const { searchParams } = url;
  const pathname = decodeURIComponent(url.pathname);
  const pathLower = pathname.toLowerCase();

  let proxyIP = defaultProxyIP;
  let enableSocks5Proxy: ChainProxyType | null = null;
  let enableSocks5GlobalProxy = false;
  let mySocks5Account = '';
  let parsedSocks5Address: ParsedProxyAddress = { hostname: '', port: 0 };
  let enableProxyFallback = defaultProxyFallback;

  const proxyCtx: ProxyContext = {
    trojanProxyAddr: null,
    proxyIP,
    proxyType: null,
    proxyAccount: '',
    proxyGlobal: false,
    proxyParams: { hostname: '', port: 0 },
    proxyFallback: enableProxyFallback,
  };

  const saveSnapshot = () => {
    proxyCtx.proxyIP = proxyIP;
    proxyCtx.proxyType = enableSocks5Proxy;
    proxyCtx.proxyAccount = mySocks5Account;
    proxyCtx.proxyGlobal = enableSocks5GlobalProxy;
    proxyCtx.proxyParams = { ...parsedSocks5Address };
    proxyCtx.proxyFallback = enableProxyFallback;
  };

  // —— L6308-6331：/video/<base64Secret> 链式代理路径（订阅生成的节点链接）——
  const chainProxyPathMatch = /\/video\/(.+)$/i.exec(pathname);
  if (chainProxyPathMatch) {
    try {
      const chainProxyPlaintext = base64SecretDecode(chainProxyPathMatch[1]!.replace(/\/+$/, ''), rctx.userId);
      const { type, ...chainProxyAddr } = JSON.parse(chainProxyPlaintext) as {
        type?: string;
        hostname?: string;
        port?: number;
        username?: string;
        password?: string;
      };
      if (!type || !CHAIN_PROXY_DEFAULT_PORT[String(type).toLowerCase()]) throw new Error('链式代理类型无效');
      if (!chainProxyAddr.hostname || !chainProxyAddr.port) throw new Error('链式代理地址缺少 hostname 或 port');
      mySocks5Account = '';
      proxyIP = '链式代理';
      enableProxyFallback = false;
      enableSocks5GlobalProxy = true;
      enableSocks5Proxy = String(type).toLowerCase() as ChainProxyType;
      parsedSocks5Address = {
        username: chainProxyAddr.username,
        password: chainProxyAddr.password,
        hostname: chainProxyAddr.hostname,
        port: Number(chainProxyAddr.port),
      };
      if (Number.isNaN(parsedSocks5Address.port)) throw new Error('链式代理端口无效');
      saveSnapshot();
      return proxyCtx;
    } catch (err) {
      rctx.error('proxy-ctx', `解析链式代理参数失败: ${(err as Error).message}`);
    }
  }

  mySocks5Account =
    searchParams.get('socks5') ||
    searchParams.get('http') ||
    searchParams.get('https') ||
    searchParams.get('turn') ||
    searchParams.get('sstp') ||
    '';
  enableSocks5GlobalProxy = searchParams.has('globalproxy');
  if (searchParams.get('socks5')) enableSocks5Proxy = 'socks5';
  else if (searchParams.get('http')) enableSocks5Proxy = 'http';
  else if (searchParams.get('https')) enableSocks5Proxy = 'https';
  else if (searchParams.get('turn')) enableSocks5Proxy = 'turn';
  else if (searchParams.get('sstp')) enableSocks5Proxy = 'sstp';

  const parseProxyUrl = (value: string, forceGlobal = true): boolean => {
    const match = /^(socks5|http|https|turn|sstp):\/\/(.+)$/i.exec(value || '');
    if (!match) return false;
    enableSocks5Proxy = match[1]!.toLowerCase() as ChainProxyType;
    mySocks5Account = match[2]!.split('/')[0]!;
    if (forceGlobal) enableSocks5GlobalProxy = true;
    return true;
  };

  const setProxyIP = (value: string) => {
    proxyIP = value;
    enableSocks5Proxy = null;
    enableProxyFallback = false;
  };

  const trojanPathMatch = /\/trojan=([^?#\s]+)/i.exec(pathname);
  if (trojanPathMatch) {
    try {
      proxyCtx.trojanProxyAddr = parseTrojanProxyAddr(trojanPathMatch[1]!.replace(/\/+$/, ''));
    } catch (err) {
      rctx.error('proxy-ctx', `解析木马反代地址失败: ${(err as Error).message}`);
      proxyCtx.trojanProxyAddr = null;
    }
  }

  const queryProxyIP = searchParams.get('proxyip');
  if (queryProxyIP !== null) {
    if (!parseProxyUrl(queryProxyIP)) {
      setProxyIP(queryProxyIP);
      saveSnapshot();
      return proxyCtx;
    }
  } else {
    let match = /\/(socks5?|http|https|turn|sstp):\/?\/?([^/?#\s]+)/i.exec(pathname);
    if (match) {
      const type = match[1]!.toLowerCase();
      enableSocks5Proxy = type === 'sock' || type === 'socks' ? 'socks5' : (type as ChainProxyType);
      mySocks5Account = match[2]!.split('/')[0]!;
      enableSocks5GlobalProxy = true;
    } else if ((match = /\/(g?s5|socks5|g?http|g?https|g?turn|g?sstp)=([^/?#\s]+)/i.exec(pathname))) {
      const type = match[1]!.toLowerCase();
      mySocks5Account = match[2]!.split('/')[0]!;
      enableSocks5Proxy = type.includes('sstp')
        ? 'sstp'
        : type.includes('turn')
          ? 'turn'
          : type.includes('https')
            ? 'https'
            : type.includes('http')
              ? 'http'
              : 'socks5';
      if (type.startsWith('g')) enableSocks5GlobalProxy = true;
    } else if ((match = /\/(proxyip[.=]|pyip=|ip=)([^?#\s]+)/.exec(pathLower))) {
      const pathProxyValue = extractPathValue(match[2]!);
      if (!parseProxyUrl(pathProxyValue)) {
        setProxyIP(pathProxyValue);
        saveSnapshot();
        return proxyCtx;
      }
    }
  }

  if (!mySocks5Account) {
    enableSocks5Proxy = null;
    saveSnapshot();
    return proxyCtx;
  }

  try {
    parsedSocks5Address = getSocks5Account(mySocks5Account, getProxyDefaultPort(enableSocks5Proxy));
    if (searchParams.get('socks5')) enableSocks5Proxy = 'socks5';
    else if (searchParams.get('http')) enableSocks5Proxy = 'http';
    else if (searchParams.get('https')) enableSocks5Proxy = 'https';
    else if (searchParams.get('turn')) enableSocks5Proxy = 'turn';
    else if (searchParams.get('sstp')) enableSocks5Proxy = 'sstp';
    else enableSocks5Proxy = enableSocks5Proxy || 'socks5';
  } catch (err) {
    rctx.error('proxy-ctx', `解析SOCKS5地址失败: ${(err as Error).message}`);
    enableSocks5Proxy = null;
  }
  saveSnapshot();
  return proxyCtx;
}
