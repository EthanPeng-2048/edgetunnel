/**
 * 伪装页插件（DESIGN.md §4.5；原 _worker.js L526-549 章节 8 兜底）。
 *
 * fallback 插件：不参与主路由链，在核心路由与其它插件全部未命中后执行
 * （与原 else-if 链落出后的行为一致）：
 * 1. env.URL 归一（'nginx' | '1101' | 域名/URL → https 源站）；
 * 2. '1101' → 内嵌 CF 1101 错误页；
 * 3. 否则反代该源站（文本响应替换源站域名），异常回落 nginx 欢迎页。
 *
 * 注意：不读 ASSETS —— /pages/*.html 只经核心路由（cookie 门禁）下发，
 * 未命中路径一律伪装页，与原实现等价。
 */
import type { RequestContext } from '../context';
import { Plugin } from './base';

/** nginx 默认欢迎页（原 nginx()，L6644-6672，逐字） */
function nginxPage(): string {
  return `
	<!DOCTYPE html>
	<html>
	<head>
	<title>Welcome to nginx!</title>
	<style>
		body {
			width: 35em;
			margin: 0 auto;
			font-family: Tahoma, Verdana, Arial, sans-serif;
		}
	</style>
	</head>
	<body>
	<h1>Welcome to nginx!</h1>
	<p>If you see this page, the nginx web server is successfully installed and
	working. Further configuration is required.</p>

	<p>For online documentation and support please refer to
	<a href="http://nginx.org/">nginx.org</a>.<br/>
	Commercial support is available at
	<a href="http://nginx.com/">nginx.com</a>.</p>

	<p><em>Thank you for using nginx.</em></p>
	</body>
	</html>
	`;
}

/** CF Worker 1101 错误页（原 html1101，L6674-6764，逐字） */
function html1101(host: string, clientIP: string): string {
  const now = new Date();
  const formatTimestamp =
    now.getFullYear() +
    '-' +
    String(now.getMonth() + 1).padStart(2, '0') +
    '-' +
    String(now.getDate()).padStart(2, '0') +
    ' ' +
    String(now.getHours()).padStart(2, '0') +
    ':' +
    String(now.getMinutes()).padStart(2, '0') +
    ':' +
    String(now.getSeconds()).padStart(2, '0');
  const randomString = Array.from(crypto.getRandomValues(new Uint8Array(8)))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  return `<!DOCTYPE html>
<!--[if lt IE 7]> <html class="no-js ie6 oldie" lang="en-US"> <![endif]-->
<!--[if IE 7]    <html class="no-js ie7 oldie" lang="en-US"> <![endif]-->
<!--[if IE 8]    <html class="no-js ie8 oldie" lang="en-US"> <![endif]-->
<!--[if gt IE 8]><!--> <html class="no-js" lang="en-US"> <!--<![endif]-->
<head>
<title>Worker threw exception | ${host} | Cloudflare</title>
<meta charset="UTF-8" />
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<meta http-equiv="X-UA-Compatible" content="IE=Edge" />
<meta name="robots" content="noindex, nofollow" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<link rel="stylesheet" id="cf_styles-css" href="/cdn-cgi/styles/cf.errors.css" />
<!--[if lt IE 9]><link rel="stylesheet" id='cf_styles-ie-css' href="/cdn-cgi/styles/cf.errors.ie.css" /><![endif]-->
<style>body{margin:0;padding:0}</style>


<!--[if gte IE 10]><!-->
<script>
  if (!navigator.cookieEnabled) {
    window.addEventListener('DOMContentLoaded', function () {
      var cookieEl = document.getElementById('cookie-alert');
      cookieEl.style.display = 'block';
    })
  }
</script>
<!--<![endif]-->

</head>
<body>
    <div id="cf-wrapper">
        <div class="cf-alert cf-alert-error cf-cookie-error" id="cookie-alert" data-translate="enable_cookies">Please enable cookies.</div>
        <div id="cf-error-details" class="cf-error-details-wrapper">
            <div class="cf-wrapper cf-header cf-error-overview">
                <h1>
                    <span class="cf-error-type" data-translate="error">Error</span>
                    <span class="cf-error-code">1101</span>
                    <small class="heading-ray-id">Ray ID: ${randomString} &bull; ${formatTimestamp} UTC</small>
                </h1>
                <h2 class="cf-subheadline" data-translate="error_desc">Worker threw exception</h2>
            </div><!-- /.header -->

            <section></section><!-- spacer -->

            <div class="cf-section cf-wrapper">
                <div class="cf-columns two">
                    <div class="cf-column">
                        <h2 data-translate="what_happened">What happened?</h2>
                            <p>You've requested a page on a website (${host}) that is on the <a href="https://www.cloudflare.com/5xx-error-landing?utm_source=error_100x" target="_blank">Cloudflare</a> network. An unknown error occurred while rendering the page.</p>
                    </div>

                    <div class="cf-column">
                        <h2 data-translate="what_can_i_do">What can I do?</h2>
                            <p><strong>If you are the owner of this website:</strong><br />refer to <a href="https://developers.cloudflare.com/workers/observability/errors/" target="_blank">Workers - Errors and Exceptions</a> and check Workers Logs for ${host}.</p>
                    </div>

                </div>
            </div><!-- /.section -->

            <div class="cf-error-footer cf-wrapper w-240 lg:w-full py-10 sm:py-4 sm:px-8 mx-auto text-center sm:text-left border-solid border-0 border-t border-gray-300">
    <p class="text-13">
      <span class="cf-footer-item sm:block sm:mb-1">Cloudflare Ray ID: <strong class="font-semibold"> ${randomString}</strong></span>
      <span class="cf-footer-separator sm:hidden">&bull;</span>
      <span id="cf-footer-item-ip" class="cf-footer-item hidden sm:block sm:mb-1">
        Your IP:
        <button type="button" id="cf-footer-ip-reveal" class="cf-footer-ip-reveal-btn">Click to reveal</button>
        <span class="hidden" id="cf-footer-ip">${clientIP}</span>
        <span class="cf-footer-separator sm:hidden">&bull;</span>
      </span>
      <span class="cf-footer-item sm:block sm:mb-1"><span>Performance &amp; security by</span> <a rel="noopener noreferrer" href="https://www.cloudflare.com/5xx-error-landing" id="brand_link" target="_blank">Cloudflare</a></span>

    </p>
    <script>(function(){function d(){var b=a.getElementById("cf-footer-item-ip"),c=a.getElementById("cf-footer-ip-reveal");b&&"classList"in b&&(b.classList.remove("hidden"),c.addEventListener("click",function(){c.classList.add("hidden"),a.getElementById("cf-footer-ip").classList.remove("hidden")}))}var a=document;document.addEventListener&&a.addEventListener("DOMContentLoaded",d)})();</script>
  </div><!-- /.error-footer -->

        </div><!-- /#cf-error-details -->
    </div><!-- /#cf-wrapper -->

     <script>
    window._cf_translation = {};


  </script>
</body>
</html>`;
}

export class FakePagePlugin extends Plugin {
  readonly name = 'fake-page';
  /** 兜底插件：不参与主路由链（router 在全部未命中后单独调用） */
  override readonly fallback = true;

  override async onRoute(rctx: RequestContext): Promise<Response | null> {
    const { request, url, env } = rctx;
    const ua = rctx.ua;

    // —— L526-532 伪装地址归一 ——
    let fakePageURL = String(env.URL || 'nginx');
    if (fakePageURL && fakePageURL !== 'nginx' && fakePageURL !== '1101') {
      fakePageURL = fakePageURL.trim().replace(/\/$/, '');
      if (!fakePageURL.match(/^https?:\/\//i)) fakePageURL = 'https://' + fakePageURL;
      if (fakePageURL.toLowerCase().startsWith('http://')) fakePageURL = 'https://' + fakePageURL.substring(7);
      try {
        const u = new URL(fakePageURL);
        fakePageURL = u.protocol + '//' + u.host;
      } catch {
        fakePageURL = 'nginx';
      }
    }

    // —— L533 1101 错误页 ——
    if (fakePageURL === '1101') {
      return new Response(html1101(url.host, rctx.clientIp), {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=UTF-8' },
      });
    }

    // —— L534-548 反代伪装源站 ——
    try {
      const proxyURL = new URL(fakePageURL);
      const newHeaders = new Headers(request.headers);
      newHeaders.set('Host', proxyURL.host);
      newHeaders.set('Referer', proxyURL.origin);
      newHeaders.set('Origin', proxyURL.origin);
      if (!newHeaders.has('User-Agent') && ua && ua !== 'null') newHeaders.set('User-Agent', ua);
      const proxyResponse = await fetch(proxyURL.origin + url.pathname + url.search, {
        method: request.method,
        headers: newHeaders,
        body: request.body,
        cf: (request as Request & { cf?: unknown }).cf,
      } as RequestInit);
      const contentType = proxyResponse.headers.get('content-type') || '';
      // 只处理文本类型的响应
      if (/text|javascript|json|xml/.test(contentType)) {
        const responseContent = (await proxyResponse.text()).replaceAll(proxyURL.host, url.host);
        return new Response(responseContent, {
          status: proxyResponse.status,
          headers: { ...Object.fromEntries(proxyResponse.headers), 'Cache-Control': 'no-store' },
        });
      }
      return proxyResponse;
    } catch {
      /* 原实现空吞 → 回落 nginx */
    }

    // —— L549 nginx 兜底 ——
    return new Response(nginxPage(), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
  }
}
