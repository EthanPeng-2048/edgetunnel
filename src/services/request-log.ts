/**
 * 请求日志（原 writeRequestLog，行为等价移植）。
 * 写 KV log.json（4MB 上限 + 30 分钟去重），TG 开启时推送 Telegram 通知。
 * 调用方通过 ctx.waitUntil 触发；函数内部全量捕获，绝不 reject。
 */
import type { Env } from '../env';
import type { Config } from '../config/schema';

export type RequestLogType =
  | 'Get_SUB'
  | 'Get_Best_SUB'
  | 'Admin_Login'
  | 'Init_Config'
  | 'Save_Config'
  | (string & {});

export async function writeRequestLog(
  env: Env,
  request: Request,
  clientIP: string,
  requestType: RequestLogType = 'Get_SUB',
  config: Config,
  writeKvLog = true,
): Promise<void> {
  try {
    const now = new Date();
    const cf = request.cf;
    const logEntry = {
      TYPE: requestType,
      IP: clientIP,
      ASN: `AS${cf?.asn || '0'} ${cf?.asOrganization || 'Unknown'}`,
      CC: `${cf?.country || 'N/A'} ${cf?.city || 'N/A'}`,
      URL: request.url,
      UA: request.headers.get('User-Agent') || 'Unknown',
      TIME: now.getTime(),
    };
    if (config.TG.enabled) {
      try {
        const TG_TXT = await env.KV!.get('tg.json');
        const TG_JSON = JSON.parse(TG_TXT || 'null') as { BotToken?: string | null; ChatID?: string | null } | null;
        if (TG_JSON?.BotToken && TG_JSON?.ChatID) {
          const requestTime = new Date(logEntry.TIME).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
          const requestUrl = new URL(logEntry.URL);
          const msg =
            `<b>#${config.bestSubGen.SUBNAME} 日志通知</b>\n\n` +
            `📌 <b>类型：</b>#${logEntry.TYPE}\n` +
            `🌐 <b>IP：</b><code>${logEntry.IP}</code>\n` +
            `📍 <b>位置：</b>${logEntry.CC}\n` +
            `🏢 <b>ASN：</b>${logEntry.ASN}\n` +
            `🔗 <b>域名：</b><code>${requestUrl.host}</code>\n` +
            `🔍 <b>路径：</b><code>${requestUrl.pathname + requestUrl.search}</code>\n` +
            `🤖 <b>UA：</b><code>${logEntry.UA}</code>\n` +
            `📅 <b>时间：</b>${requestTime}\n` +
            `${
              config.CF.Usage.success
                ? `📊 <b>请求用量：</b>${config.CF.Usage.total}/${config.CF.Usage.max} <b>${((config.CF.Usage.total / config.CF.Usage.max) * 100).toFixed(2)}%</b>\n`
                : ''
            }`;
          await fetch(`https://api.telegram.org/bot${TG_JSON.BotToken}/sendMessage?chat_id=${TG_JSON.ChatID}&parse_mode=HTML&text=${encodeURIComponent(msg)}`, {
            method: 'GET',
            headers: {
              Accept: 'text/html,application/xhtml+xml,application/xml;',
              'Accept-Encoding': 'gzip, deflate, br',
              'User-Agent': logEntry.UA || 'Unknown',
            },
          });
        }
      } catch (error) {
        console.error(`读取tg.json出错: ${(error as Error).message}`);
      }
    }
    writeKvLog = ['1', 'true'].includes(String(env.OFF_LOG)) ? false : writeKvLog;
    if (!writeKvLog) return;
    let logArray: unknown[] = [];
    const existingLogs = await env.KV!.get('log.json');
    const KV_SIZE_LIMIT_MB = 4;
    if (existingLogs) {
      try {
        logArray = JSON.parse(existingLogs);
        if (!Array.isArray(logArray)) {
          logArray = [logEntry];
        } else if (requestType !== 'Get_SUB') {
          const thirtyMinAgoTs = now.getTime() - 30 * 60 * 1000;
          if (
            logArray.some(
              (log) =>
                typeof log === 'object' &&
                log !== null &&
                (log as { TYPE?: string }).TYPE !== 'Get_SUB' &&
                (log as { IP?: string }).IP === clientIP &&
                (log as { URL?: string }).URL === request.url &&
                (log as { UA?: string }).UA === (request.headers.get('User-Agent') || 'Unknown') &&
                ((log as { TIME?: number }).TIME ?? 0) >= thirtyMinAgoTs,
            )
          )
            return;
          logArray.push(logEntry);
          while (JSON.stringify(logArray, null, 2).length > KV_SIZE_LIMIT_MB * 1024 * 1024 && logArray.length > 0) logArray.shift();
        } else {
          logArray.push(logEntry);
          while (JSON.stringify(logArray, null, 2).length > KV_SIZE_LIMIT_MB * 1024 * 1024 && logArray.length > 0) logArray.shift();
        }
      } catch {
        logArray = [logEntry];
      }
    } else {
      logArray = [logEntry];
    }
    await env.KV!.put('log.json', JSON.stringify(logArray, null, 2));
  } catch (error) {
    console.error(`日志记录失败: ${(error as Error).message}`);
  }
}
