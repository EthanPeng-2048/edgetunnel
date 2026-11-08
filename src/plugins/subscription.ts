/**
 * 订阅插件（DESIGN.md §4.5；原 _worker.js 章节 7 —— L107 快速订阅 + L325 /sub 全流程）。
 *
 * 认领路径（插件链最先，顺序与原 else-if 链等价）：
 * 1. fast-sub：caseSensitivePath === KEY（且 KEY 非默认值）→ 302 /sub?token=MD5MD5(host+uuid)
 * 2. sub：token 校验（客户端 token / 日切后端 token / 优选生成器哨兵）→ 本地生成或订阅转换；
 *    token 不匹配返回 null（原实现落出 else-if 链 → 伪装页兜底）。
 *
 * 兼容红线：cookie/token 日切算法、品牌 UA、中文文案、节点链接格式逐字保留。
 */
import type { RequestContext } from '../context';
import { DEFAULT_ENCRYPTION_SECRET, detectISPFromRequest } from '../context';
import type { Config } from '../config/schema';
import { Plugin } from './base';
import { md5Md5 } from '../services/md5';
import { base64SecretEncode } from '../services/base64-secret';
import { loadConfig } from '../config/loader';
import { writeRequestLog } from '../services/request-log';
import { BRAND_OWNER, EDT_VERSION } from '../services/brand';
import { getTransportConfig, getTransportPathValue, randomPath } from '../config/transport';
import { ensureArray } from '../utils/array';
import { generateRandomIPs, fetchBestIPApi, fetchBestSubGeneratorData, replaceAsterisks } from '../services/bestip';
import { applyClashPatch, applySingboxPatch, applySurgePatch } from '../services/sub-patch';
import { getSocks5Account, getProxyDefaultPort } from '../forward/proxy-ctx';

const PLACEHOLDER_UUID = '00000000-0000-4000-8000-000000000000';
const PLACEHOLDER_UUID_B64 = 'MDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDAw';

/** 统一正则: 匹配 域名/IPv4/IPv6地址 + 可选端口 + 可选备注（原 L431 逐字） */
const NODE_ADDRESS_RE =
  /^(\[[\da-fA-F:]+\]|[\d.]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(?::(\d+))?(?:#(.+))?$/;

export class SubscriptionPlugin extends Plugin {
  readonly name = 'subscription';

  override async onRoute(rctx: RequestContext): Promise<Response | null> {
    const caseSensitivePath = rctx.url.pathname.slice(1);
    const requestPath = caseSensitivePath.toLowerCase();

    // —— L107 快速订阅：路径即 KEY → 302 带 token（KEY 为默认值时禁用）——
    if (caseSensitivePath === rctx.encryptionSecret && rctx.encryptionSecret !== DEFAULT_ENCRYPTION_SECRET) {
      const params = new URLSearchParams(rctx.url.search);
      params.set('token', md5Md5(rctx.host + rctx.userId));
      return new Response('重定向中...', { status: 302, headers: { 'Location': `/sub?${params.toString()}` } });
    }

    // —— L325 订阅 ——
    if (requestPath === 'sub') return this.handleSub(rctx);
    return null;
  }

  /** 原 L325-517 订阅请求全流程；token 全不匹配返回 null（落出分支 → 伪装页兜底） */
  private async handleSub(rctx: RequestContext): Promise<Response | null> {
    const { request, url, env } = rctx;
    const ua = rctx.ua;
    const uaLower = ua.toLowerCase();
    const host = rctx.host;
    const userID = rctx.userId;
    const identityHeader = rctx.identity[0];
    // —— token 体系（L326-335）：在 loadConfig 之前计算（原实现在 L336 条件内才加载配置）——
    const subToken = md5Md5(host + userID);
    const asBestSubGenerator =
      ['1', 'true'].includes(String(env.BEST_SUB ?? '')) &&
      url.searchParams.get('host') === 'example.com' &&
      url.searchParams.get('uuid') === PLACEHOLDER_UUID &&
      uaLower.includes(`tunnel (https://github.com/${BRAND_OWNER}/edge`);
    const requestToken = url.searchParams.get('token');
    const clientRequestsSub = requestToken === subToken;
    const currentDayIndex = Math.floor(Date.now() / 86400000);
    const subBackendTokenSeed = base64SecretEncode(subToken, userID);
    const [todaySubBackendToken, yesterdaySubBackendToken] = [
      md5Md5(subBackendTokenSeed + currentDayIndex),
      md5Md5(subBackendTokenSeed + (currentDayIndex - 1)),
    ];
    const subBackendFetchSub = requestToken === todaySubBackendToken || requestToken === yesterdaySubBackendToken;

    if (!(clientRequestsSub || subBackendFetchSub || asBestSubGenerator)) {
      // token 全不匹配 → 原实现落出 else-if 链（伪装页兜底），无日志无副作用
      return null;
    }

    // L337 配置加载（副作用：缺省初始化写 KV、TG/CF 默认文件）
    const config = await loadConfig(rctx);

    // L338-339 日志
    if (asBestSubGenerator) {
      rctx.ctx.waitUntil(writeRequestLog(env, request, rctx.clientIp, 'Get_Best_SUB', config, false));
    } else {
      rctx.ctx.waitUntil(writeRequestLog(env, request, rctx.clientIp, 'Get_SUB', config));
    }

    // L341-346 响应头
    const responseHeaders: Record<string, string> = {
      'content-type': 'text/plain; charset=utf-8',
      'Profile-Update-Interval': String(config.bestSubGen.SUBUpdateTime),
      'Profile-web-page-url': url.protocol + '//' + url.host + '/admin',
      'Cache-Control': 'no-store',
    };
    // L347-352 用量信息
    if (config.CF.Usage.success) {
      const pagesSum = config.CF.Usage.pages;
      const workersSum = config.CF.Usage.workers;
      const total = Number.isFinite(config.CF.Usage.max) ? (config.CF.Usage.max / 1000) * 1024 : 1024 * 100;
      responseHeaders['Subscription-Userinfo'] = `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=4102329600`;
    }

    // L353 判定 subconverter 请求（ua 已小写）
    const isSubConverterRequest =
      url.searchParams.has('b64') ||
      url.searchParams.has('base64') ||
      !!request.headers.get('subconverter-request') ||
      !!request.headers.get('subconverter-version') ||
      uaLower.includes('subconverter') ||
      uaLower.includes('cf-workers-sub') ||
      asBestSubGenerator;

    // L354-368 订阅类型级联
    const subType = isSubConverterRequest
      ? 'mixed'
      : url.searchParams.has('target')
        ? url.searchParams.get('target')!
        : url.searchParams.has('clash') || uaLower.includes('clash') || uaLower.includes('meta') || uaLower.includes('mihomo')
          ? 'clash'
          : url.searchParams.has('sb') || url.searchParams.has('singbox') || uaLower.includes('singbox') || uaLower.includes('sing-box')
            ? 'singbox'
            : url.searchParams.has('surge') || uaLower.includes('surge')
              ? 'surge&ver=4'
              : url.searchParams.has('quanx') || uaLower.includes('quantumult')
                ? 'quanx'
                : url.searchParams.has('loon') || uaLower.includes('loon')
                  ? 'loon'
                  : 'mixed';

    // L370 附件下载头
    if (!uaLower.includes('mozilla')) {
      responseHeaders['Content-Disposition'] = `attachment; filename*=utf-8''${encodeURIComponent(config.bestSubGen.SUBNAME)}`;
    }
    // L371 surge 且非 ss → trojan
    const isSurgeClient = url.searchParams.has('surge') || uaLower.includes('surge');
    const protocolType = isSurgeClient && config.protocolType !== 'ss' ? 'trojan' : config.protocolType;

    let subContent = '';
    if (subType === 'mixed') {
      subContent = await this.renderMixedSub(rctx, config, {
        uaLower,
        asBestSubGenerator,
        isSubConverterRequest,
        protocolType,
      });
    } else {
      // —— L478-488 订阅转换 ——
      const subConverterUrl =
        `${config.subConverterConfig.SUBAPI}/sub?target=${subType}` +
        `&url=${encodeURIComponent(
          url.protocol +
            '//' +
            url.host +
            '/sub?target=mixed&token=' +
            todaySubBackendToken +
            '&cnIspCode=' +
            detectISPFromRequest(request) +
            (url.searchParams.has('sub') && url.searchParams.get('sub') !== '' ? `&sub=${url.searchParams.get('sub')}` : ''),
        )}` +
        `&config=${encodeURIComponent(config.subConverterConfig.SUBCONFIG)}` +
        `&emoji=${config.subConverterConfig.SUBEMOJI}` +
        `&list=${config.subConverterConfig.SUBLIST}` +
        `&scv=${config.skipCertVerify}` +
        `&xudp=${config.subConverterConfig.XUDP}` +
        `&udp=${config.subConverterConfig.UDP}` +
        `&tls13=${config.subConverterConfig.TLS13}` +
        `&append_type=${config.subConverterConfig.APPEND_TYPE}` +
        `&sort=${config.subConverterConfig.SORT}` +
        `&expand=${config.subConverterConfig.EXPAND}`;
      try {
        const response = await fetch(subConverterUrl, {
          headers: {
            'User-Agent':
              'Subconverter for ' +
              subType +
              ' edge' +
              'tunnel (https://github.com/' +
              BRAND_OWNER +
              '/edge' +
              'tunnel) Uid/0x' +
              identityHeader +
              ' Version/' +
              EDT_VERSION,
          },
        });
        if (response.ok) {
          subContent = await response.text();
          if (isSurgeClient) {
            subContent = applySurgePatch(subContent, url.protocol + '//' + url.host + '/sub?token=' + subToken + '&surge', config);
          }
        } else {
          return new Response('订阅转换后端异常：' + response.statusText, { status: response.status });
        }
      } catch (error) {
        return new Response('订阅转换后端异常：' + (error as Error).message, { status: 403 });
      }
    }

    // L491-505 UUID / HOST 占位替换（仅客户端直连 token）
    if (!uaLower.includes('subconverter') && clientRequestsSub) {
      const shuffledHosts = [...config.HOSTS].sort(() => Math.random() - 0.5);
      let hostReplaceCount = 0;
      let currentRandomHost: string | undefined;
      subContent = subContent
        .replace(new RegExp(PLACEHOLDER_UUID, 'g'), config.UUID)
        .replace(new RegExp(PLACEHOLDER_UUID_B64, 'g'), btoa(config.UUID))
        .replace(/example\.com/g, () => {
          if (hostReplaceCount % 2 === 0) {
            const originalHost = shuffledHosts[Math.floor(hostReplaceCount / 2) % shuffledHosts.length]!;
            currentRandomHost = replaceAsterisks(originalHost);
          }
          hostReplaceCount++;
          return currentRandomHost!;
        });
    }

    // L507 mixed 且（非浏览器 UA 或显式 b64）→ base64 外壳
    if (subType === 'mixed' && (!uaLower.includes('mozilla') || url.searchParams.has('b64') || url.searchParams.has('base64'))) {
      subContent = btoa(subContent);
    }

    // L509-515 Clash / Singbox 热补丁与 content-type
    if (subType === 'singbox') {
      subContent = await applySingboxPatch(subContent, config);
      responseHeaders['content-type'] = 'application/json; charset=utf-8';
    } else if (subType === 'clash') {
      subContent = applyClashPatch(subContent, config);
      responseHeaders['content-type'] = 'application/x-yaml; charset=utf-8';
    }

    return new Response(subContent, { status: 200, headers: responseHeaders });
  }

  /** L373-477 mixed 订阅正文（本地 IP 库 / 优选订阅生成器两条路径） */
  private async renderMixedSub(
    rctx: RequestContext,
    config: Config,
    opts: {
      uaLower: string;
      asBestSubGenerator: boolean;
      isSubConverterRequest: boolean;
      protocolType: string;
    },
  ): Promise<string> {
    const { request, url, env } = rctx;
    const { uaLower, asBestSubGenerator, isSubConverterRequest, protocolType } = opts;
    const identityHeader = rctx.identity[0];

    // L374 TLS 分片参数
    const tlsFragmentParams =
      config.tlsFragment == 'Shadowrocket'
        ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}`
        : config.tlsFragment == 'Happ'
          ? `&fragment=${encodeURIComponent('3,1,tlshello')}`
          : '';

    let fullBestIP: string[] = [];
    let otherNodeLinks = '';
    let proxyIPPool: string[] = [];

    if (!url.searchParams.has('sub') && config.bestSubGen.local) {
      // —— L377-415 本地生成订阅 ——
      const { randomCount, fixedPort, randomIP } = config.bestSubGen.localIPPool;
      let fullBestIPList: string[];
      if (randomIP) {
        fullBestIPList = (await generateRandomIPs(request, randomCount, fixedPort))[0];
      } else {
        const addTxt = await env.KV!.get('ADD.txt');
        fullBestIPList = addTxt ? ensureArray(addTxt) : (await generateRandomIPs(request, randomCount, fixedPort))[0];
      }

      const bestIPApi: string[] = [];
      const bestIP: string[] = [];
      const otherNodes: string[] = [];
      for (const element of fullBestIPList) {
        if (element.toLowerCase().startsWith('sub://')) {
          bestIPApi.push(element);
        } else {
          const remarkPos = element.indexOf('#');
          const addressPart = remarkPos > -1 ? element.slice(0, remarkPos) : element;
          const remarkPart = remarkPos > -1 ? element.slice(remarkPos) : '';
          const subMatch = element.match(/sub\s*=\s*([^\s&#]+)/i);
          if (subMatch && subMatch[1]!.trim().includes('.')) {
            const bestIPAsProxyIP = element.toLowerCase().includes('proxyip=true');
            const remarkSuffix = element.includes('#') ? '#' + element.split('#')[1]! : '';
            if (bestIPAsProxyIP) bestIPApi.push('sub://' + subMatch[1]!.trim() + '?proxyip=true' + remarkSuffix);
            else bestIPApi.push('sub://' + subMatch[1]!.trim() + remarkSuffix);
          } else if (addressPart.toLowerCase().startsWith('https://')) {
            bestIPApi.push(element);
          } else if (addressPart.toLowerCase().includes('://')) {
            if (element.includes('#')) {
              const splitAddrRemark = element.split('#');
              otherNodes.push(splitAddrRemark[0]! + '#' + encodeURIComponent(decodeURIComponent(splitAddrRemark[1]!)));
            } else {
              otherNodes.push(element);
            }
          } else {
            if (addressPart.includes('*')) bestIP.push(replaceAsterisks(addressPart) + remarkPart);
            else bestIP.push(element);
          }
        }
      }

      const bestIPApiContent = await fetchBestIPApi(bestIPApi, '443', identityHeader);
      const mergeOtherNodesArray = [...new Set(otherNodes.concat(bestIPApiContent[1]))];
      otherNodeLinks = mergeOtherNodesArray.length > 0 ? mergeOtherNodesArray.join('\n') + '\n' : '';
      const bestIPApiResults = bestIPApiContent[0];
      proxyIPPool = bestIPApiContent[3] || [];
      fullBestIP = [...new Set(bestIP.concat(bestIPApiResults))];
    } else {
      // —— L416-421 优选订阅生成器 ——
      const bestSubGeneratorHost = url.searchParams.get('sub') || config.bestSubGen.SUB!;
      const [bestGenIPList, bestGenOtherNodes] = await fetchBestSubGeneratorData(bestSubGeneratorHost, identityHeader);
      fullBestIP = fullBestIP.concat(bestGenIPList);
      otherNodeLinks += bestGenOtherNodes;
    }

    // L422-424
    const echLinkParams = config.ECH
      ? `&ech=${encodeURIComponent((config.ECHConfig.SNI ? config.ECHConfig.SNI + '+' : '') + config.ECHConfig.DNS)}`
      : '';
    const isLoonOrSurge = uaLower.includes('loon') || uaLower.includes('surge');
    const { type: transport, pathFieldName, hostFieldName } = getTransportConfig(config);

    // L425-477 节点链接渲染
    const nodeLinks = fullBestIP
      .map((originalAddress): string | null => {
        const match = originalAddress.match(NODE_ADDRESS_RE);
        let nodeAddress: string;
        let nodePort = '443';
        let nodeRemark: string;
        if (match) {
          nodeAddress = match[1]!;
          nodePort = match[2] ? match[2] : '443';
          nodeRemark = match[3] || nodeAddress;
        } else {
          console.warn(`[订阅内容] 不规范的IP格式已忽略: ${originalAddress}`);
          return null;
        }

        let fullNodePath = config.fullNodePath;

        // L448-461 节点备注内链式代理指令 / ProxyIP 池匹配
        const chainProxyMatch = nodeRemark.match(/\$(socks5|http|https|turn|sstp):\/\/([^#\s]+)/i);
        if (chainProxyMatch) {
          try {
            const proxyProtocol = chainProxyMatch[1]!.toLowerCase();
            const proxyParams = chainProxyMatch[2]!;
            const chainProxyData = {
              type: proxyProtocol,
              ...getSocks5Account(proxyParams, getProxyDefaultPort(proxyProtocol)),
            };
            fullNodePath = `/video/${base64SecretEncode(JSON.stringify(chainProxyData), rctx.userId)}${
              config.enable0RTT ? '?ed=2560' : ''
            }`;
            nodeRemark = nodeRemark.replace(chainProxyMatch[0], '').trim() || nodeAddress;
          } catch (error) {
            console.warn(
              `[订阅内容] 链式代理解析失败，已忽略该指令: ${chainProxyMatch[0]} (${
                (error as Error)?.message ? (error as Error).message : error
              })`,
            );
          }
        } else if (proxyIPPool.length > 0) {
          const matchedProxyIP = proxyIPPool.find((p) => p.includes(nodeAddress));
          if (matchedProxyIP) {
            fullNodePath = (`${config.PATH}/proxyip=${matchedProxyIP}`).replace(/\/\//g, '/') + (config.enable0RTT ? '?ed=2560' : '');
          }
        }
        if (isLoonOrSurge) fullNodePath = fullNodePath.replace(/,/g, '%2C');

        // L464-476 协议链接
        if (protocolType === 'ss' && !asBestSubGenerator) {
          if (!config.SS.TLS) {
            const TLS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
            const NO_TLS_PORTS = [80, 2052, 2082, 2086, 2095, 8080];
            nodePort = String(NO_TLS_PORTS[TLS_PORTS.indexOf(Number(nodePort))] ?? nodePort);
          }
          fullNodePath = (
            fullNodePath.includes('?')
              ? fullNodePath.replace('?', '?enc=' + config.SS.encryptionMethod + '&')
              : fullNodePath + '?enc=' + config.SS.encryptionMethod
          ).replace(/([=,])/g, '\\$1');
          if (!isSubConverterRequest) fullNodePath = fullNodePath + ';mux=0';
          return `${protocolType}://${btoa(config.SS.encryptionMethod + ':' + PLACEHOLDER_UUID)}@${nodeAddress}:${nodePort}?plugin=v2${encodeURIComponent(
            'ray-plugin;mode=websocket;host=example.com;path=' +
              (config.randomPath ? randomPath(fullNodePath) : fullNodePath) +
              (config.SS.TLS ? ';tls' : ''),
          )}${echLinkParams}${tlsFragmentParams}#${encodeURIComponent(nodeRemark)}`;
        }
        const transportPathValue = getTransportPathValue(config, fullNodePath, asBestSubGenerator);
        return `${protocolType}://${PLACEHOLDER_UUID}@${nodeAddress}:${nodePort}?security=tls&type=${transport + echLinkParams}&${hostFieldName}=example.com&fp=${config.Fingerprint}&sni=example.com&${pathFieldName}=${encodeURIComponent(
          transportPathValue,
        ) + tlsFragmentParams}&encryption=none&alpn=${encodeURIComponent(config.ALPN)}#${encodeURIComponent(nodeRemark)}`;
      })
      .filter((item): item is string => item !== null)
      .join('\n');

    return otherNodeLinks + nodeLinks;
  }
}
