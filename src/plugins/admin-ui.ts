/**
 * 管理 API 插件（DESIGN.md §4.5 AdminUiPlugin 的 API 部分；
 * 原 _worker.js admin 分支中登录/管理页核心路由之外的子 API，L132-317）。
 *
 * 认领路径（全部带原 L131 cookie 门禁 → 无效 302 /login）：
 * - 加载配置**之前**短路（原 L228 loadConfig 之前）：log.json、getCloudflareUsage、check
 * - 加载配置**之后**（本插件自行 loadConfig 以复现原 L228 副作用）：
 *   cf.json GET/POST、tg.json POST、ADD.txt GET/POST（大小写敏感，与原 caseSensitivePath 一致）
 * - admin/config.json、admin/init、管理页兜底仍由 router 核心处理。
 *
 * check（原 L158-225）：链式代理健康检查 —— 经 chainRegistry 拨号 cloudflare.com:443，
 * 自研 TLS 内层握手后抓 /cdn-cgi/trace 的 ip=/loc=，恒 200 返回 JSON。
 */
import type { RequestContext } from '../context';
import { verifyAuthCookie } from '../auth';
import { loadConfig } from '../config/loader';
import { writeRequestLog } from '../services/request-log';
import { getCloudflareUsage } from '../services/cf-usage';
import { generateRandomIPs } from '../services/bestip';
import { getSocks5Account, getProxyDefaultPort } from '../forward/proxy-ctx';
import { createRequestTcpConnector } from '../forward/dialer';
import { chainRegistry } from '../chain/registry';
import type { ChainSocket } from '../chain/base';
import { TlsClient } from '../chain/tls/client';
import { concatByteChunks } from '../utils/bytes';
import { Plugin } from './base';
import { jsonResponse, redirectResponse } from './respond';

const CHAIN_TYPES = ['socks5', 'http', 'https', 'turn', 'sstp'] as const;

interface CheckResult {
  success: boolean;
  proxy: string;
  ip?: string;
  loc?: string;
  error?: string;
  responseTime: number;
}

export class AdminUiPlugin extends Plugin {
  readonly name = 'admin-api';

  override async onRoute(rctx: RequestContext): Promise<Response | null> {
    const caseSensitivePath = rctx.url.pathname.slice(1);
    const requestPath = caseSensitivePath.toLowerCase();
    if (requestPath !== 'admin' && !requestPath.startsWith('admin/')) return null;

    // —— 原 L131 admin 分支 cookie 门禁 ——
    if (!(await verifyAuthCookie(rctx.request, rctx.encryptionSecret, rctx.adminPassword!))) {
      return redirectResponse('/login');
    }

    // —— L228 loadConfig **之前**短路的三个（原结构：先于配置加载，无 KV 副作用）——
    if (requestPath === 'admin/log.json') return this.handleLog(rctx);
    if (caseSensitivePath === 'admin/getCloudflareUsage') return this.handleUsage(rctx);
    if (requestPath === 'admin/check') return this.handleCheck(rctx);

    // —— L228 之后的分支：本插件自行 loadConfig（复现原配置加载副作用与日志用 config）——
    if (caseSensitivePath === 'admin/ADD.txt') return this.handleAddTxt(rctx);
    if (requestPath === 'admin/cf.json') return this.handleCfJson(rctx);
    if (requestPath === 'admin/tg.json' && rctx.request.method === 'POST') return this.handleTgJson(rctx);

    return null;
  }

  /** L132-134：读取日志内容（任意方法，先于 loadConfig） */
  private async handleLog(rctx: RequestContext): Promise<Response> {
    const readLogContent = (await rctx.env.KV!.get('log.json')) || '[]';
    return new Response(readLogContent, { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
  }

  /** L135-142：查询 CF 请求量（先于 loadConfig；成功头无 charset，与原一致） */
  private async handleUsage(rctx: RequestContext): Promise<Response> {
    const { url } = rctx;
    try {
      const Usage_JSON = await getCloudflareUsage(
        url.searchParams.get('Email'),
        url.searchParams.get('GlobalAPIKey'),
        url.searchParams.get('AccountID'),
        url.searchParams.get('APIToken'),
      );
      return new Response(JSON.stringify(Usage_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
    } catch (err) {
      const error = err as Error;
      return jsonResponse({ msg: '查询请求量失败，失败原因：' + error.message, error: error.message }, 500, true);
    }
  }

  /** L158-225：代理检查（先于 loadConfig；恒 200） */
  private async handleCheck(rctx: RequestContext): Promise<Response> {
    const { request, url } = rctx;
    const proxyProtocol = CHAIN_TYPES.find((type) => url.searchParams.has(type)) ?? null;
    if (!proxyProtocol) {
      return jsonResponse({ error: '缺少代理参数' }, 400, false);
    }
    const proxyParams = url.searchParams.get(proxyProtocol)!;
    const startTime = Date.now();
    let detectProxyResponse: CheckResult;
    try {
      const checkParsed = getSocks5Account(proxyParams, getProxyDefaultPort(proxyProtocol));
      const { username, password, hostname, port } = checkParsed;
      const fullProxyParams = username && password ? `${username}:${password}@${hostname}:${port}` : `${hostname}:${port}`;
      try {
        const detectHost = 'cloudflare.com';
        const detectPort = 443;
        const encoder = new TextEncoder();
        const decoder = new TextDecoder();
        const tcpConnect = createRequestTcpConnector(request);
        let tcpSocket: ChainSocket | null = null;
        let tlsSocket: TlsClient | null = null;
        try {
          // 原按类型分派 socks5Connect/turnConnect/sstpConnect/httpsConnect/httpConnect ——
          // 统一为 chainRegistry 拨号（五 Provider 与原五函数一一对应）
          const provider = chainRegistry.get(proxyProtocol);
          if (!provider) throw new Error('无法连接到代理服务器');
          const dialResult = await provider.dial({
            proxy: checkParsed,
            target: { host: detectHost, port: detectPort },
            initialData: new Uint8Array(0),
            tcpConnect,
          });
          tcpSocket = dialResult.socket;
          if (!tcpSocket) throw new Error('无法连接到代理服务器');
          tlsSocket = new TlsClient(tcpSocket, { serverName: detectHost, insecure: true });
          await tlsSocket.handshake();
          await tlsSocket.write(
            encoder.encode(`GET /cdn-cgi/trace HTTP/1.1\r\nHost: ${detectHost}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n`),
          );
          let responseBuffer: Uint8Array = new Uint8Array(0);
          let headerEndIndex = -1;
          let contentLength: number | null = null;
          let chunked = false;
          const maxResponseBytes = 64 * 1024;
          while (responseBuffer.length < maxResponseBytes) {
            const value = await tlsSocket.read();
            if (!value) break;
            if (value.byteLength === 0) continue;
            responseBuffer = concatByteChunks(responseBuffer, value);
            if (headerEndIndex === -1) {
              const crlfcrlf = responseBuffer.findIndex(
                (_, i) =>
                  i < responseBuffer.length - 3 &&
                  responseBuffer[i] === 0x0d &&
                  responseBuffer[i + 1] === 0x0a &&
                  responseBuffer[i + 2] === 0x0d &&
                  responseBuffer[i + 3] === 0x0a,
              );
              if (crlfcrlf !== -1) {
                headerEndIndex = crlfcrlf + 4;
                const headers = decoder.decode(responseBuffer.slice(0, headerEndIndex));
                const statusLine = headers.split('\r\n')[0] || '';
                const statusMatch = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
                const statusCode = statusMatch ? parseInt(statusMatch[1]!, 10) : NaN;
                if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) {
                  throw new Error(`代理检测请求失败: ${statusLine || '无效响应'}`);
                }
                const lengthMatch = headers.match(/\r\nContent-Length:\s*(\d+)/i);
                if (lengthMatch) contentLength = parseInt(lengthMatch[1]!, 10);
                chunked = /\r\nTransfer-Encoding:\s*chunked/i.test(headers);
              }
            }
            if (headerEndIndex !== -1 && contentLength !== null && responseBuffer.length >= headerEndIndex + contentLength) break;
            if (headerEndIndex !== -1 && chunked && decoder.decode(responseBuffer).includes('\r\n0\r\n\r\n')) break;
          }
          if (headerEndIndex === -1) throw new Error('代理检测响应头过长或无效');
          const response = decoder.decode(responseBuffer);
          const ip = response.match(/(?:^|\n)ip=(.*)/)?.[1];
          const loc = response.match(/(?:^|\n)loc=(.*)/)?.[1];
          if (!ip || !loc) throw new Error('代理检测响应无效');
          detectProxyResponse = {
            success: true,
            proxy: proxyProtocol + '://' + fullProxyParams,
            ip,
            loc,
            responseTime: Date.now() - startTime,
          };
        } finally {
          try {
            if (tlsSocket) tlsSocket.close();
            else await tcpSocket?.close?.();
          } catch {
            /* 原空吞 */
          }
        }
      } catch (error) {
        detectProxyResponse = {
          success: false,
          error: (error as Error).message,
          proxy: proxyProtocol + '://' + fullProxyParams,
          responseTime: Date.now() - startTime,
        };
      }
    } catch (err) {
      detectProxyResponse = {
        success: false,
        error: (err as Error).message,
        proxy: proxyProtocol + '://' + proxyParams,
        responseTime: Date.now() - startTime,
      };
    }
    return jsonResponse(detectProxyResponse, 200, true);
  }

  /** L298-314：自定义优选 IP（POST 保存 / 非 POST 返回，大小写敏感；需 loadConfig） */
  private async handleAddTxt(rctx: RequestContext): Promise<Response> {
    const { request, env } = rctx;
    const config = await loadConfig(rctx);
    if (request.method === 'POST') {
      try {
        const customIPs = await request.text();
        await env.KV!.put('ADD.txt', customIPs);
        rctx.ctx.waitUntil(writeRequestLog(env, request, rctx.clientIp, 'Save_Custom_IPs', config));
        return jsonResponse({ success: true, message: '自定义IP已保存' }, 200, false);
      } catch (error) {
        console.error('保存自定义IP失败:', error);
        return jsonResponse({ error: `保存自定义IP失败: ${(error as Error).message}` }, 500, false);
      }
    }
    // GET（及其它非 POST 方法，与原 else-if 链一致）
    let localBestIP = (await env.KV!.get('ADD.txt')) || 'null';
    if (localBestIP == 'null') {
      localBestIP = (
        await generateRandomIPs(request, config.bestSubGen.localIPPool.randomCount, config.bestSubGen.localIPPool.fixedPort)
      )[1];
    }
    return new Response(localBestIP, {
      status: 200,
      headers: { 'Content-Type': 'text/plain;charset=utf-8', 'asn': String(rctx.cf?.asn) },
    });
  }

  /** L256-281 / L315-316：cf.json（POST 保存 / 非 POST 返回 request.cf；需 loadConfig） */
  private async handleCfJson(rctx: RequestContext): Promise<Response> {
    const { request, env } = rctx;
    const config = await loadConfig(rctx);
    if (request.method === 'POST') {
      try {
        const newConfig = (await request.json()) as Record<string, unknown>;
        const CF_JSON: Record<string, string | null> = {
          Email: null,
          GlobalAPIKey: null,
          AccountID: null,
          APIToken: null,
          UsageAPI: null,
        };
        if (!newConfig.init || newConfig.init !== true) {
          if (newConfig.Email && newConfig.GlobalAPIKey) {
            CF_JSON.Email = newConfig.Email as string;
            CF_JSON.GlobalAPIKey = newConfig.GlobalAPIKey as string;
          } else if (newConfig.AccountID && newConfig.APIToken) {
            CF_JSON.AccountID = newConfig.AccountID as string;
            CF_JSON.APIToken = newConfig.APIToken as string;
          } else if (newConfig.UsageAPI) {
            CF_JSON.UsageAPI = newConfig.UsageAPI as string;
          } else {
            return jsonResponse({ error: '配置不完整' }, 400, false);
          }
        }
        await env.KV!.put('cf.json', JSON.stringify(CF_JSON, null, 2));
        rctx.ctx.waitUntil(writeRequestLog(env, request, rctx.clientIp, 'Save_Config', config));
        return jsonResponse({ success: true, message: '配置已保存' }, 200, false);
      } catch (error) {
        console.error('保存配置失败:', error);
        return jsonResponse({ error: `保存配置失败: ${(error as Error).message}` }, 500, false);
      }
    }
    return jsonResponse(rctx.cf ?? {}, 200, true);
  }
  /** L282-297：tg.json（仅 POST 认领；需 loadConfig 供日志） */
  private async handleTgJson(rctx: RequestContext): Promise<Response> {
    const { request, env } = rctx;
    const config = await loadConfig(rctx);
    try {
      const newConfig = (await request.json()) as Record<string, unknown>;
      if (newConfig.init && newConfig.init === true) {
        const TG_JSON = { BotToken: null, ChatID: null };
        await env.KV!.put('tg.json', JSON.stringify(TG_JSON, null, 2));
      } else {
        if (!newConfig.BotToken || !newConfig.ChatID) return jsonResponse({ error: '配置不完整' }, 400, false);
        await env.KV!.put('tg.json', JSON.stringify(newConfig, null, 2));
      }
      rctx.ctx.waitUntil(writeRequestLog(env, request, rctx.clientIp, 'Save_Config', config));
      return jsonResponse({ success: true, message: '配置已保存' }, 200, false);
    } catch (error) {
      console.error('保存配置失败:', error);
      return jsonResponse({ error: `保存配置失败: ${(error as Error).message}` }, 500, false);
    }
  }
}
