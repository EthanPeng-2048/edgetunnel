/**
 * DoH 查询（原 _worker.js dohQuery，行为等价移植）。
 *
 * 模块级缓存属启动期只读优化层（与被消除的「每请求可变全局」不同）：
 * 缓存只影响解析延迟，不影响正确性。
 */
import { TunnelError } from '../errors';

export interface DohAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

const DOH_RECORD_TYPE_MAP: Record<string, number> = {
  A: 1,
  NS: 2,
  CNAME: 5,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  HTTPS: 65,
};

const DOH_CACHE_MAX_ENTRIES = 256;
const dohCache = new Map<string, { data: string[]; expireTime: number }>();

function encodeDomainName(name: string): Uint8Array {
  const parts = name.endsWith('.') ? name.slice(0, -1).split('.') : name.split('.');
  const bufs: Uint8Array[] = [];
  for (const label of parts) {
    const enc = new TextEncoder().encode(label);
    bufs.push(new Uint8Array([enc.length]), enc);
  }
  bufs.push(new Uint8Array([0]));
  let total = 0;
  for (const b of bufs) total += b.length;
  const result = new Uint8Array(total);
  let off = 0;
  for (const b of bufs) {
    result.set(b, off);
    off += b.length;
  }
  return result;
}

/** 解析 DNS 域名（处理指针压缩）—— 原 parseDomainName 内联逻辑 */
function parseDomainName(buf: Uint8Array, pos: number): [string, number] {
  const labels: string[] = [];
  let p = pos;
  let jumped = false;
  let endPos = -1;
  let safe = 128;
  while (p < buf.length && safe-- > 0) {
    const len = buf[p]!;
    if (len === 0) {
      if (!jumped) endPos = p + 1;
      break;
    }
    if ((len & 0xc0) === 0xc0) {
      if (!jumped) endPos = p + 2;
      p = ((len & 0x3f) << 8) | buf[p + 1]!;
      jumped = true;
      continue;
    }
    labels.push(new TextDecoder().decode(buf.subarray(p + 1, p + 1 + len)));
    p += len + 1;
  }
  if (endPos === -1) endPos = p + 1;
  return [labels.join('.'), endPos];
}

/**
 * DoH 查询（POST dns-message → Cloudflare DNS）。
 * 失败返回 []（原实现 catch 后 console.error + 空数组，不抛）。
 */
export async function dohQuery(
  domain: string,
  recordType: string,
  dohResolver = 'https://cloudflare-dns.com/dns-query',
): Promise<DohAnswer[]> {
  const normalizeDomain = String(domain || '')
    .trim()
    .toLowerCase()
    .replace(/\.$/, '');
  const normalizeRecordType = String(recordType || '')
    .trim()
    .toUpperCase();
  const cacheKey = `${normalizeDomain}:${normalizeRecordType}`;
  const qtype = DOH_RECORD_TYPE_MAP[normalizeRecordType] || 1;
  const currentTs = Date.now();
  const existing = dohCache.get(cacheKey);
  if (existing && currentTs < existing.expireTime) {
    return existing.data.map((data) => ({ name: normalizeDomain, type: qtype, TTL: 0, data }));
  }

  const startTime = performance.now();
  try {
    const qname = encodeDomainName(normalizeDomain);
    const query = new Uint8Array(12 + qname.length + 4);
    const qview = new DataView(query.buffer);
    qview.setUint16(0, crypto.getRandomValues(new Uint16Array(1))[0]!);
    qview.setUint16(2, 0x0100); // RD=1
    qview.setUint16(4, 1); // QDCOUNT
    query.set(qname, 12);
    qview.setUint16(12 + qname.length, qtype);
    qview.setUint16(12 + qname.length + 2, 1); // QCLASS = IN

    const response = await fetch(dohResolver, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/dns-message',
        Accept: 'application/dns-message',
      },
      body: query,
    });
    if (!response.ok) {
      console.warn(`[DoH查询] 请求失败 ${domain} ${recordType} via ${dohResolver} 响应代码:${response.status}`);
      return [];
    }

    const buf = new Uint8Array(await response.arrayBuffer());
    const dv = new DataView(buf.buffer);
    const qdcount = dv.getUint16(4);
    const ancount = dv.getUint16(6);

    let offset = 12;
    for (let i = 0; i < qdcount; i++) {
      const [, end] = parseDomainName(buf, offset);
      offset = end + 4;
    }

    const answers: DohAnswer[] = [];
    for (let i = 0; i < ancount && offset < buf.length; i++) {
      const [name, nameEnd] = parseDomainName(buf, offset);
      offset = nameEnd;
      const type = dv.getUint16(offset);
      offset += 2;
      offset += 2; // CLASS
      const ttl = dv.getUint32(offset);
      offset += 4;
      const rdlen = dv.getUint16(offset);
      offset += 2;
      const rdata = buf.subarray(offset, offset + rdlen);
      offset += rdlen;

      let data: string;
      if (type === 1 && rdlen === 4) {
        data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
      } else if (type === 28 && rdlen === 16) {
        const segs: string[] = [];
        for (let j = 0; j < 16; j += 2) segs.push((((rdata[j]! << 8) | rdata[j + 1]!) >>> 0).toString(16));
        data = segs.join(':');
      } else if (type === 16) {
        let tOff = 0;
        const parts: string[] = [];
        while (tOff < rdlen) {
          const tLen = rdata[tOff++]!;
          parts.push(new TextDecoder().decode(rdata.subarray(tOff, tOff + tLen)));
          tOff += tLen;
        }
        data = parts.join('');
      } else if (type === 5) {
        const [cname] = parseDomainName(buf, offset - rdlen);
        data = cname;
      } else {
        data = Array.from(rdata)
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');
      }
      answers.push({ name, type, TTL: ttl, data });
    }

    // 缓存：至少 5 分钟；响应 TTL 更长时尊重 TTL；空结果用 5 分钟负缓存
    const related = answers.filter((a) => a.type === qtype);
    const minTtl = related.length > 0 ? Math.min(...related.map((a) => a.TTL)) : 0;
    const cacheTtl = Math.max(minTtl, 5 * 60);
    const cachedData = related.map((a) => a.data);
    if (cachedData.length > 0 || answers.length === 0) {
      if (dohCache.size >= DOH_CACHE_MAX_ENTRIES) {
        const cleanupTs = Date.now();
        for (const [k, v] of [...dohCache]) {
          if (cleanupTs >= v.expireTime) dohCache.delete(k);
        }
        if (dohCache.size >= DOH_CACHE_MAX_ENTRIES) {
          const first = dohCache.keys().next().value;
          if (first !== undefined) dohCache.delete(first);
        }
      }
      dohCache.set(cacheKey, { data: cachedData, expireTime: Date.now() + cacheTtl * 1000 });
    }
    void startTime;
    return answers;
  } catch (error) {
    console.error(`[DoH查询] 查询失败 ${domain} ${recordType} via ${dohResolver}:`, error);
    return [];
  }
}

/** 测试用：清空 DoH 缓存 */
export function clearDohCache(): void {
  dohCache.clear();
}

// 保留 TunnelError 引用以防后续扩展需要（当前 dohQuery 按原实现不抛）
void TunnelError;
