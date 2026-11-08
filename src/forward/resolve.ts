/**
 * 反代地址解析（原 _worker.js resolveAddrPort，行为等价移植）。
 *
 * proxyIP 支持：纯 IP 直用 / 域名走 DoH（TXT → A → AAAA）；
 * 结果按 target 域 + UUID 种子做确定性洗牌，取前 8 个。
 */
import type { RequestContext } from '../context';
import { dohQuery } from '../services/doh';
import { ensureArray } from '../utils/array';
import { isIPv4 } from '../utils/net';

const IPV4_REGEX = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
const IPV6_REGEX = /^\[?(?:[a-fA-F0-9]{0,4}:){1,7}[a-fA-F0-9]{0,4}\]?$/;

function parseHostPortString(str: string): [string, number] {
  let address = str;
  let port = 443;
  if (str.includes(']:')) {
    const parts = str.split(']:');
    address = parts[0] + ']';
    port = parseInt(parts[1]!, 10) || port;
  } else if ((str.match(/:/g) || []).length === 1 && !str.startsWith('[')) {
    const colonIndex = str.lastIndexOf(':');
    address = str.slice(0, colonIndex);
    port = parseInt(str.slice(colonIndex + 1), 10) || port;
  }
  return [address, port];
}

function parseTxtProxyRecords(txtData: string[]): Array<[string, number]> {
  return txtData
    .flatMap((data) => {
      if (data.startsWith('"') && data.endsWith('"')) data = data.slice(1, -1);
      return data
        .replace(/\\010/g, ',')
        .replace(/\n/g, ',')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
    })
    .map((prefix) => parseHostPortString(prefix));
}

/**
 * 解析反代 IP 列表（原 resolveAddrPort）。
 * 返回 [host, port] 元组数组（最多 8 个，确定性洗牌）。
 */
export async function resolveAddrPort(
  ctx: RequestContext,
  proxyIP: string | string[],
  targetDomain = 'dash.cloudflare.com',
  uuid = '00000000-0000-4000-8000-000000000000',
): Promise<Array<[string, number]>> {
  const normalized = String(proxyIP || '').toLowerCase();
  const proxyIPList = ensureArray(normalized);
  const allProxyList: Array<[string, number]> = [];

  for (const singleProxyIP of proxyIPList) {
    let [address, port] = parseHostPortString(singleProxyIP);

    if (singleProxyIP.includes('.tp')) {
      const tpMatch = singleProxyIP.match(/\.tp(\d+)/);
      if (tpMatch) port = parseInt(tpMatch[1]!, 10);
    }

    if (IPV4_REGEX.test(address) || IPV6_REGEX.test(address)) {
      ctx.log('[反代解析]', `${address} 为IP地址，直接使用`);
      allProxyList.push([address, port]);
      continue;
    }

    const [txtRecords, aRecords] = await Promise.all([dohQuery(address, 'TXT'), dohQuery(address, 'A')]);

    const txtData = txtRecords.filter((r) => r.type === 16).map((r) => r.data);
    const txtAddresses = parseTxtProxyRecords(txtData);
    if (txtAddresses.length > 0) {
      ctx.log('[反代解析]', `${address} 使用TXT记录，共${txtAddresses.length}个结果`);
      allProxyList.push(...txtAddresses);
      continue;
    }

    const ipv4List = aRecords.filter((r) => r.type === 1).map((r) => r.data);
    if (ipv4List.length > 0) {
      ctx.log('[反代解析]', `${address} 未获取到TXT记录，使用A记录，共${ipv4List.length}个结果`);
      allProxyList.push(...ipv4List.map((ip) => [ip, port] as [string, number]));
      continue;
    }

    const aaaaRecords = await dohQuery(address, 'AAAA');
    const ipv6List = aaaaRecords.filter((r) => r.type === 28).map((r) => `[${r.data}]`);
    if (ipv6List.length > 0) {
      ctx.log('[反代解析]', `${address} 未获取到TXT和A记录，使用AAAA记录，共${ipv6List.length}个结果`);
      allProxyList.push(...ipv6List.map((ip) => [ip, port] as [string, number]));
    } else {
      ctx.log('[反代解析]', `${address} 未获取到TXT、A和AAAA记录，保留原域名`);
      allProxyList.push([address, port]);
    }
  }

  const sortedArray = allProxyList.sort((a, b) => a[0]!.localeCompare(b[0]!));
  const targetRootDomain = targetDomain.includes('.') ? targetDomain.split('.').slice(-2).join('.') : targetDomain;
  let randomSeed = [...(targetRootDomain + uuid)].reduce((a, c) => a + c.charCodeAt(0), 0);
  const shuffled = [...sortedArray].sort(() => (randomSeed = (randomSeed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff - 0.5);
  return shuffled.slice(0, 8);
}

void isIPv4;
