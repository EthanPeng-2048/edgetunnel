/**
 * 优选 IP 与最佳订阅生成（原 replaceAsterisks L5460-5468、generateRandomIPs L5995-6026、
 * fetchBestSubGeneratorData L6036-6085、fetchBestIPApi L6087-6289，行为等价移植）。
 *
 * - replaceAsterisks：通配符替换为 3~16 位随机字母数字
 * - generateRandomIPs：拉取 CF CIDR 列表（失败兜底 104.16.0.0/13）后生成随机 IP:端口#备注
 * - fetchBestSubGeneratorData：解析优选订阅生成器占位订阅（base64），拆优选IP 与其他节点 LINK
 * - fetchBestIPApi：并发拉取多源订阅（纯文本 / CSV / base64 LINK / sub://），输出四元组
 *   [优选IP, LINK数组, 需转换URL（原实现仅声明恒为空数组）, ProxyIP池]
 */
import { detectISPFromRequest } from '../context';
import { ensureArray } from '../utils/array';
import { BRAND_OWNER, CLUSTER_SUB_UA, EDT_VERSION } from './brand';

/** 通配符替换为随机串（原 replaceAsterisks，L5460-5468）：每个 * 换成 3~16 位小写字母数字 */
export function replaceAsterisks(content: string): string {
	if (typeof content !== 'string' || !content.includes('*')) return content;
	const charset = 'abcdefghijklmnopqrstuvwxyz0123456789';
	return content.replace(/\*/g, () => {
		let s = '';
		for (let i = 0; i < Math.floor(Math.random() * 14) + 3; i++) s += charset[Math.floor(Math.random() * charset.length)]!;
		return s;
	});
}

/**
 * 本地 CIDR 随机 IP 生成（原 generateRandomIPs，L5995-6026）。
 * cnIspCode 查询参数优先，否则用 detectISPFromRequest（原 detectISP）判定运营商；
 * 返回 [IP:端口#备注 列表, 上述列表换行拼接]。
 */
export async function generateRandomIPs(request: Request, count = 16, fixedPort = -1): Promise<[string[], string]> {
	const url = new URL(request.url);
	const queryParamIsp = String(url.searchParams.get('cnIspCode') || '').toLowerCase();
	const ispFileId = ['ct', 'cu', 'cmcc', 'cf'].includes(queryParamIsp) ? queryParamIsp : detectISPFromRequest(request);
	const ISP_NAME_MAP: Record<string, string> = {
		cmcc: 'CF移动优选',
		cu: 'CF联通优选',
		ct: 'CF电信优选',
		cf: 'CF官方优选',
	};
	const cidr_url = ispFileId === 'cf' ? `https://raw.githubusercontent.com/${BRAND_OWNER}/${BRAND_OWNER}/main/CF-CIDR.txt` : `https://raw.githubusercontent.com/${BRAND_OWNER}/${BRAND_OWNER}/main/CF-CIDR/${ispFileId}.txt`;
	const cfname = ISP_NAME_MAP[ispFileId] || 'CF官方优选';
	const cfport = [443, 2053, 2083, 2087, 2096, 8443];
	let cidrList: string[] = [];
	try { const res = await fetch(cidr_url); cidrList = res.ok ? ensureArray(await res.text()) : ['104.16.0.0/13'] } catch { cidrList = ['104.16.0.0/13'] }

	// CIDR 内随机 IP：基地址掩码对齐 + 随机主机位偏移（! 仅编译期，运行时 undefined→NaN 与原实现一致）
	const generateRandomIPFromCIDR = (cidr: string): string => {
		const [baseIP, prefixLength] = cidr.split('/'), prefix = parseInt(prefixLength!), hostBits = 32 - prefix;
		const ipInt = baseIP!.split('.').reduce((a, p, i) => a | (parseInt(p) << (24 - i * 8)), 0);
		const randomOffset = Math.floor(Math.random() * Math.pow(2, hostBits));
		const mask = (0xFFFFFFFF << hostBits) >>> 0, randomIP = (((ipInt & mask) >>> 0) + randomOffset) >>> 0;
		return [(randomIP >>> 24) & 0xFF, (randomIP >>> 16) & 0xFF, (randomIP >>> 8) & 0xFF, randomIP & 0xFF].join('.');
	};
	const randomIPs = Array.from({ length: count }, (_, index) => {
		const ip = generateRandomIPFromCIDR(cidrList[Math.floor(Math.random() * cidrList.length)]!);
		const targetPort = fixedPort === -1
			? cfport[Math.floor(Math.random() * cfport.length)]
			: fixedPort;
		return `${ip}:${targetPort}#${cfname}${index + 1}`;
	});
	return [randomIPs, randomIPs.join('\n')];
}

/**
 * 最佳订阅生成器拉取（原 fetchBestSubGeneratorData，L6036-6085）。
 * 请求 `${origin}/sub?host=example.com&uuid=00000000-...`（UA 带 Uid/Version），
 * base64 解码后拆出占位行的 域名:端口#备注 与其余节点 LINK；任何异常以
 * `127.0.0.1:1234#...` 备注行形式折入优选IP 数组返回。
 */
export async function fetchBestSubGeneratorData(bestSubGeneratorHost: string, uid = '000000'): Promise<[string[], string]> {
	let bestIP: string[] = [], otherNodeLinks = '', formatHost = bestSubGeneratorHost.replace(/^sub:\/\//i, 'https://').split('#')[0]!.split('?')[0]!;
	if (!/^https?:\/\//i.test(formatHost)) formatHost = `https://${formatHost}`;

	try {
		const url = new URL(formatHost);
		formatHost = url.origin;
	} catch (error) {
		bestIP.push(`127.0.0.1:1234#${bestSubGeneratorHost}优选订阅生成器格式化异常:${(error as Error).message}`);
		return [bestIP, otherNodeLinks];
	}

	const bestSubGeneratorUrl = `${formatHost}/sub?host=example.com&uuid=00000000-0000-4000-8000-000000000000`;

	try {
		const response = await fetch(bestSubGeneratorUrl, {
			headers: { 'User-Agent': CLUSTER_SUB_UA + ' Uid/0x' + uid + ' Version/' + EDT_VERSION }
		});

		if (!response.ok) {
			bestIP.push(`127.0.0.1:1234#${bestSubGeneratorHost}优选订阅生成器异常:${response.statusText}`);
			return [bestIP, otherNodeLinks];
		}

		const bestGenSubContent = atob(await response.text());
		const subLineList = bestGenSubContent.includes('\r\n')
			? bestGenSubContent.split('\r\n')
			: bestGenSubContent.split('\n');

		for (const lineContent of subLineList) {
			if (!lineContent.trim()) continue; // 跳过空行
			if (lineContent.includes('00000000-0000-4000-8000-000000000000') && lineContent.includes('example.com')) {
				// 这是优选IP行，提取 域名:端口#备注
				const addressMatch = lineContent.match(/:\/\/[^@]+@([^?]+)/);
				if (addressMatch) {
					let addrPort = addressMatch[1]!, remark = ''; // 域名:端口 或 IP:端口
					const remarkMatch = lineContent.match(/#(.+)$/);
					if (remarkMatch) remark = '#' + decodeURIComponent(remarkMatch[1]!);
					bestIP.push(addrPort + remark);
				}
			} else {
				otherNodeLinks += lineContent + '\n';
			}
		}
	} catch (error) {
		bestIP.push(`127.0.0.1:1234#${bestSubGeneratorHost}优选订阅生成器异常:${(error as Error).message}`);
	}

	return [bestIP, otherNodeLinks];
}

/**
 * 多源订阅拉取解析（原 fetchBestIPApi，L6087-6289）。
 * sub:// 前缀走 fetchBestSubGeneratorData；其余并发 fetch（UA 同上，AbortController 超时），
 * 按响应内容分支处理 LINK 文本 / 纯 IP 列表 / CSV（IP地址表 与 优选测速表）。
 * 返回四元组：[优选IP 去重, LINK 去重, needsSubConverterUrls（原实现仅声明未填充）, ProxyIP 池]。
 */
export async function fetchBestIPApi(urls: string[], defaultPort = '443', uid = '000000', timeoutMs = 3000): Promise<[string[], string[], string[], string[]]> {
	if (!urls?.length) return [[], [], [], []];
	const results = new Set<string>(), proxyIPPool = new Set<string>();
	let subResponsePlainLinks = '', needsSubConverterUrls: string[] = [];
	await Promise.allSettled(urls.map(async (url) => {
		// 检查URL是否包含备注名
		const hashIndex = url.indexOf('#');
		const urlWithoutHash = hashIndex > -1 ? url.substring(0, hashIndex) : url;
		const apiRemarkName = hashIndex > -1 ? decodeURIComponent(url.substring(hashIndex + 1)) : null;
		const bestIPAsProxyIP = url.toLowerCase().includes('proxyip=true');
		if (urlWithoutHash.toLowerCase().startsWith('sub://')) {
			try {
				const [bestIP, otherNodeLinks] = await fetchBestSubGeneratorData(urlWithoutHash, uid);
				// 处理第一个数组 - 优选IP
				if (apiRemarkName) {
					for (const ip of bestIP) {
						const processedIP = ip.includes('#')
							? `${ip} [${apiRemarkName}]`
							: `${ip}#[${apiRemarkName}]`;
						results.add(processedIP);
						if (bestIPAsProxyIP) proxyIPPool.add(ip.split('#')[0]!);
					}
				} else {
					for (const ip of bestIP) {
						results.add(ip);
						if (bestIPAsProxyIP) proxyIPPool.add(ip.split('#')[0]!);
					}
				}
				// 处理第二个数组 - 其他节点LINK
				if (otherNodeLinks && typeof otherNodeLinks === 'string' && apiRemarkName) {
					const processedLinkContent = otherNodeLinks.replace(/([a-z][a-z0-9+\-.]*:\/\/[^\r\n]*?)(\r?\n|$)/gi, (match: string, link: string, lineEnd: string) => {
						const fullLink = link.includes('#')
							? `${link}${encodeURIComponent(` [${apiRemarkName}]`)}`
							: `${link}${encodeURIComponent(`#[${apiRemarkName}]`)}`;
						return `${fullLink}${lineEnd}`;
					});
					subResponsePlainLinks += processedLinkContent;
				} else if (otherNodeLinks && typeof otherNodeLinks === 'string') {
					subResponsePlainLinks += otherNodeLinks;
				}
			} catch (e) { }
			return;
		}

		try {
			const controller = new AbortController();
			const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
			const response = await fetch(urlWithoutHash, { signal: controller.signal, headers: { 'User-Agent': CLUSTER_SUB_UA + ' Uid/0x' + uid + ' Version/' + EDT_VERSION } });
			clearTimeout(timeoutId);
			let text = '';
			try {
				const buffer = await response.arrayBuffer();
				const contentType = (response.headers.get('content-type') || '').toLowerCase();
				const charset = contentType.match(/charset=([^\s;]+)/i)?.[1]?.toLowerCase() || '';

				// 根据 Content-Type 响应头判断编码优先级
				let decoders = ['utf-8', 'gb2312']; // 默认优先 UTF-8
				if (charset.includes('gb') || charset.includes('gbk') || charset.includes('gb2312')) {
					decoders = ['gb2312', 'utf-8']; // 如果明确指定 GB 系编码，优先尝试 GB2312
				}

				// 尝试多种编码解码
				let decodeSuccess = false;
				for (const decoder of decoders) {
					try {
						const decoded = new TextDecoder(decoder).decode(buffer);
						// 验证解码结果的有效性
						if (decoded && decoded.length > 0 && !decoded.includes('\ufffd')) {
							text = decoded;
							decodeSuccess = true;
							break;
						} else if (decoded && decoded.length > 0) {
							// 如果有替换字符 (U+FFFD)，说明编码不匹配，继续尝试下一个编码
							continue;
						}
					} catch (e) {
						// 该编码解码失败，尝试下一个
						continue;
					}
				}

				// 如果所有编码都失败或无效，尝试 response.text()
				if (!decodeSuccess) {
					text = await response.text();
				}

				// 如果返回的是空或无效数据，返回
				if (!text || text.trim().length === 0) {
					return;
				}
			} catch (e) {
				console.error('Failed to decode response:', e);
				return;
			}

			// 预处理订阅内容
			/*
			if (text.includes('proxies:') || (text.includes('outbounds"') && text.includes('inbounds"'))) {// Clash Singbox 配置
				需要订阅转换订阅URLs.add(url);
				return;
			}
			*/

			let preprocessedSubPlaintext = text;
			const cleanText = typeof text === 'string' ? text.replace(/\s/g, '') : '';
			if (cleanText.length > 0 && cleanText.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(cleanText)) {
				try {
					const bytes: Uint8Array = new Uint8Array(atob(cleanText).split('').map(c => c.charCodeAt(0)));
					preprocessedSubPlaintext = new TextDecoder('utf-8').decode(bytes);
				} catch { }
			}
			if (preprocessedSubPlaintext.split('#')[0]!.includes('://')) {
				// 处理LINK内容
				if (apiRemarkName) {
					const processedLinkContent = preprocessedSubPlaintext.replace(/([a-z][a-z0-9+\-.]*:\/\/[^\r\n]*?)(\r?\n|$)/gi, (match: string, link: string, lineEnd: string) => {
						const fullLink = link.includes('#')
							? `${link}${encodeURIComponent(` [${apiRemarkName}]`)}`
							: `${link}${encodeURIComponent(`#[${apiRemarkName}]`)}`;
						return `${fullLink}${lineEnd}`;
					});
					subResponsePlainLinks += processedLinkContent + '\n';
				} else {
					subResponsePlainLinks += preprocessedSubPlaintext + '\n';
				}
				return;
			}

			const lines = text.trim().split('\n').map(l => l.trim()).filter(l => l);
			const isCSV = lines.length > 1 && lines[0]!.includes(',');
			const IPV6_PATTERN = /^[^\[\]]*:[^\[\]]*:[^\[\]]/;
			const parsedUrl = new URL(urlWithoutHash);
			if (!isCSV) {
				lines.forEach(line => {
					const lineHashIndex = line.indexOf('#');
					const [hostPart, remark] = lineHashIndex > -1 ? [line.substring(0, lineHashIndex), line.substring(lineHashIndex)] : [line, ''];
					let hasPort = false;
					if (hostPart!.startsWith('[')) {
						hasPort = /\]:(\d+)$/.test(hostPart!);
					} else {
						const colonIndex = hostPart!.lastIndexOf(':');
						hasPort = colonIndex > -1 && /^\d+$/.test(hostPart!.substring(colonIndex + 1));
					}
					const port = parsedUrl.searchParams.get('port') || defaultPort;
					const ipItem = hasPort ? line : `${hostPart}:${port}${remark}`;
					// 处理第一个数组 - 优选IP
					if (apiRemarkName) {
						const processedIP = ipItem.includes('#')
							? `${ipItem} [${apiRemarkName}]`
							: `${ipItem}#[${apiRemarkName}]`;
						results.add(processedIP);
					} else {
						results.add(ipItem);
					}
					if (bestIPAsProxyIP) proxyIPPool.add(ipItem.split('#')[0]!);
				});
			} else {
				const headers = lines[0]!.split(',').map(h => h.trim());
				const dataLines = lines.slice(1);
				if (headers.includes('IP地址') && headers.includes('端口') && headers.includes('数据中心')) {
					const ipIdx = headers.indexOf('IP地址'), portIdx = headers.indexOf('端口');
					const remarkIdx = headers.indexOf('国家') > -1 ? headers.indexOf('国家') :
						headers.indexOf('城市') > -1 ? headers.indexOf('城市') : headers.indexOf('数据中心');
					const tlsIdx = headers.indexOf('TLS');
					dataLines.forEach(line => {
						const cols = line.split(',').map(c => c.trim());
						if (tlsIdx !== -1 && cols[tlsIdx]?.toLowerCase() !== 'true') return;
						const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]!) ? `[${cols[ipIdx]}]` : cols[ipIdx];
						const ipItem = `${wrappedIP}:${cols[portIdx]}#${cols[remarkIdx]}`;
						// 处理第一个数组 - 优选IP
						if (apiRemarkName) {
							const processedIP = `${ipItem} [${apiRemarkName}]`;
							results.add(processedIP);
						} else {
							results.add(ipItem);
						}
						if (bestIPAsProxyIP) proxyIPPool.add(`${wrappedIP}:${cols[portIdx]}`);
					});
				} else if (headers.some(h => h.includes('IP')) && headers.some(h => h.includes('延迟')) && headers.some(h => h.includes('下载速度'))) {
					const ipIdx = headers.findIndex(h => h.includes('IP'));
					const delayIdx = headers.findIndex(h => h.includes('延迟'));
					const speedIdx = headers.findIndex(h => h.includes('下载速度'));
					const port = parsedUrl.searchParams.get('port') || defaultPort;
					dataLines.forEach(line => {
						const cols = line.split(',').map(c => c.trim());
						const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]!) ? `[${cols[ipIdx]}]` : cols[ipIdx];
						const ipItem = `${wrappedIP}:${port}#CF优选 ${cols[delayIdx]}ms ${cols[speedIdx]}MB/s`;
						// 处理第一个数组 - 优选IP
						if (apiRemarkName) {
							const processedIP = `${ipItem} [${apiRemarkName}]`;
							results.add(processedIP);
						} else {
							results.add(ipItem);
						}
						if (bestIPAsProxyIP) proxyIPPool.add(`${wrappedIP}:${port}`);
					});
				}
			}
		} catch (e) { }
	}));
	// 将LINK内容转换为数组并去重
	const linkArray = subResponsePlainLinks.trim() ? [...new Set(subResponsePlainLinks.split(/\r?\n/).filter(line => line.trim() !== ''))] : [];
	return [Array.from(results), linkArray, needsSubConverterUrls, Array.from(proxyIPPool)];
}
