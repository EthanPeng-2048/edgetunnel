/**
 * edgetunnel 下游自制版 —— 单文件 Cloudflare Worker（VLESS / Trojan / Shadowsocks 边缘隧道）
 *
 * 传输层：WebSocket、gRPC、xHTTP；出站：直连 / ProxyIP 反代 / SOCKS5·HTTP·HTTPS·TURN·SSTP 链式代理。
 * 入口：export default.fetch —— 按 Upgrade 头、POST、路径分发到传输层与管理后台/订阅路由。
 *
 * 章节索引（后续 TS 多文件拆分的模块边界）：
 *   1. 全局常量与品牌常量
 *   2. fetch 主入口（路由 / 认证 / 后台 / 订阅）
 *   3. xHTTP / gRPC / WebSocket 传输层
 *   4. 协议解析（VLESS / Trojan / SS）与 SS 加密
 *   5. TCP/UDP 转发核心（连接世代、链式调度、Grain 合包队列）
 *   6. 链式代理客户端（SOCKS5 / HTTP / HTTPS + 自研 TLS + TURN + SSTP）
 *   7. 订阅热补丁、配置加载与键名迁移、DoH、优选、反代解析
 *   8. HTML 伪装页
 *
 * 已知全局可变状态（拆分时优先消除）：
 *   config_JSON —— 模块级，loadConfig 每请求覆写；同一 isolate 的并发请求会互相覆盖。
 */
const Version = '2026-10-08 22:23:27';
// 模块级可变状态：config_JSON 见文件头说明；其余为每请求从 env 覆写的调优参数
let config_JSON, cachedSocks5Whitelist = null, debugLogging = false;
let socks5Whitelist = ['*tapecontent.net', '*cloudatacdn.com', '*loadshare.org', '*cdn-centaurus.com', 'scholar.google.com'];
const PAGES_SITE_URL = 'https://edt-pages.github.io', EDT_VERSION = Number(String(Version).replace(/\D+/g, ''));
///////////////////////////////////////////////////////全局调优常量（合包/队列/并发）///////////////////////////////////////////////
const WS_EARLY_DATA_MAX_BYTES = 8 * 1024, WS_EARLY_DATA_MAX_HEADER = Math.ceil(WS_EARLY_DATA_MAX_BYTES * 4 / 3) + 4;
const UPLINK_COALESCE_TARGET_BYTES = 20 * 1024, UPLINK_QUEUE_MAX_BYTES = 16 * 1024 * 1024, UPLINK_QUEUE_MAX_ITEMS = 4096;
const DOWNLINK_GRAIN_CHUNK_BYTES = 32 * 1024, DOWNLINK_GRAIN_TAIL_THRESHOLD = 512, DOWNLINK_GRAIN_LOW_WATER_BYTES = Math.max(4096, DOWNLINK_GRAIN_TAIL_THRESHOLD * 12), DOWNLINK_GRAIN_MAX_WAIT_ROUNDS = 4;
let tcpConcurrentDial = 2, proxyConcurrentDial = 1, preloadRaceDial = false;
/////////////////////////////////////////////////////////品牌常量///////////////////////////////////////////////
// 原上游用运行时拼接（Proxy.name / String.fromCharCode / 数字反转）绕过静态检索；
// 下游 TS 编译产物自带混淆，这里直接写成字面量。值与原运行结果完全一致。
const BRAND_PROXYIP = 'PROXYIP';   // 原 (Proxy.name + 'IP').toUpperCase()
const BRAND_OWNER = 'cmliu';       // 原 String.fromCharCode(67,109) + URL.name[2] + 'i' + URL.name[0]
const BRAND_TP1_ID = '090227';     // 原 String(2407 * 300 - 10) 反转
const CLUSTER_SUB_UA = `v2rayN/edgetunnel (https://github.com/${BRAND_OWNER}/edgetunnel)`;
///////////////////////////////////////////////////////fetch 主入口（路由 / 认证 / 后台 / 订阅）///////////////////////////////////////////////
export default {
	async fetch(request, env, ctx) {
		let requestUrlText = request.url.replace(/%5[Cc]/g, '').replace(/\\/g, '');
		const requestUrlHashIndex = requestUrlText.indexOf('#');
		const requestUrlMain = requestUrlHashIndex === -1 ? requestUrlText : requestUrlText.slice(0, requestUrlHashIndex);
		if (!requestUrlMain.includes('?') && /%3f/i.test(requestUrlMain)) {
			const requestUrlHashPart = requestUrlHashIndex === -1 ? '' : requestUrlText.slice(requestUrlHashIndex);
			requestUrlText = requestUrlMain.replace(/%3f/i, '?') + requestUrlHashPart;
		}
		const url = new URL(requestUrlText);
		const UA = request.headers.get('User-Agent') || 'null';
		const upgradeHeader = (request.headers.get('Upgrade') || '').toLowerCase(), contentType = (request.headers.get('content-type') || '').toLowerCase();
		const adminPassword = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY || env.UUID || env.uuid;
		const encryptionSecret = env.KEY || '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改';
		const userIDMD5 = await MD5MD5(adminPassword + encryptionSecret);
		const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
		const envUUID = env.UUID || env.uuid;
		const userID = (envUUID && uuidRegex.test(envUUID)) ? envUUID.toLowerCase() : [userIDMD5.slice(0, 8), userIDMD5.slice(8, 12), '4' + userIDMD5.slice(13, 16), '8' + userIDMD5.slice(17, 20), userIDMD5.slice(20)].join('-');
		const hosts = env.HOST ? (await ensureArray(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]) : [url.hostname];
		const host = hosts[0];
		const requestPath = url.pathname.slice(1).toLowerCase();
		debugLogging = ['1', 'true'].includes(env.DEBUG) || debugLogging;
		preloadRaceDial = ['1', 'true'].includes(env.PRELOAD_RACE_DIAL) || preloadRaceDial;
		proxyConcurrentDial = Math.max(1, Number(env.PROXY_CONCURRENT_DIAL) || proxyConcurrentDial);
		tcpConcurrentDial = Math.max(1, Number(env.TCP_CONCURRENT_DIAL) || tcpConcurrentDial);
		if (!env.TCP_CONCURRENT_DIAL && tcpConcurrentDial !== 1 && detectISP(request) === 'cmcc') tcpConcurrentDial = 1;
		let defaultProxyIP = (`${request.cf.colo}.${BRAND_PROXYIP}.${BRAND_OWNER}SsSs.nEt`).toLowerCase(), defaultProxyFallback = true;
		if (env.PROXYIP) {
			const proxyIPs = await ensureArray(env.PROXYIP);
			defaultProxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
			defaultProxyFallback = false;
		};
		const clientIP = request.headers.get('CF-Connecting-IP') || request.headers.get('True-Client-IP') || request.headers.get('X-Real-IP') || request.headers.get('X-Forwarded-For') || request.headers.get('Fly-Client-IP') || request.headers.get('X-Appengine-Remote-Addr') || request.headers.get('X-Cluster-Client-IP') || '未知IP';
		const [identityHeader, identityKey] = getIdentity(userID);
		if (cachedSocks5Whitelist === null) {
			if (env.GO2SOCKS5) socks5Whitelist = [...new Set(socks5Whitelist.concat(await ensureArray(env.GO2SOCKS5)))];
			cachedSocks5Whitelist = socks5Whitelist;
		} else socks5Whitelist = cachedSocks5Whitelist;
		if (requestPath === 'version') {// 版本信息接口
			const requestUuid = (url.searchParams.get('uuid') || '').toLowerCase();
			if (uuidRegex.test(requestUuid)) {
				const targetUuid = String(userID).toLowerCase();
				let requestFirst8Sum = 0, targetFirst8Sum = 0;
				for (let i = 0; i < 8; i++) {
					const requestCode = requestUuid.charCodeAt(i);
					requestFirst8Sum += requestCode <= 57 ? requestCode - 48 : requestCode - 87;
					const targetCode = targetUuid.charCodeAt(i);
					targetFirst8Sum += targetCode <= 57 ? targetCode - 48 : targetCode - 87;
				}
				if (requestFirst8Sum === targetFirst8Sum && requestUuid.slice(-12) === targetUuid.slice(-12)) return new Response(JSON.stringify({ Version: EDT_VERSION }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
			}
		} else if (adminPassword && upgradeHeader === 'websocket') {// WebSocket代理
			const proxyCtx = await getProxyParams(url, userID, defaultProxyIP, defaultProxyFallback);
			log(`[WebSocket] 命中请求: ${url.pathname}${url.search}`);
			return await handleWsRequest(request, userID, url, proxyCtx);
		} else if (adminPassword && !requestPath.startsWith('admin/') && requestPath !== 'login' && request.method === 'POST') {// gRPC/叉HTTP代理
			const proxyCtx = await getProxyParams(url, userID, defaultProxyIP, defaultProxyFallback);
			const hitXhttpSignal = !!request.headers.get(identityHeader) || !!url.searchParams.get(identityKey);
			if (!hitXhttpSignal && contentType.startsWith('application/grpc')) {
				log(`[gRPC] 命中请求: ${url.pathname}${url.search}`);
				return await handleGrpcRequest(request, userID, proxyCtx);
			}
			log(`[叉HTTP] 命中请求: ${url.pathname}${url.search}`);
			return await handleXhttpRequest(request, userID, proxyCtx);
		} else {
			if (url.protocol === 'http:') return Response.redirect(url.href.replace(`http://${url.hostname}`, `https://${url.hostname}`), 301);
			if (!adminPassword) return fetch(PAGES_SITE_URL + '/noADMIN').then(r => { const headers = new Headers(r.headers); headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate'); headers.set('Pragma', 'no-cache'); headers.set('Expires', '0'); return new Response(r.body, { status: 404, statusText: r.statusText, headers }) });
			if (env.KV && typeof env.KV.get === 'function') {
				const caseSensitivePath = url.pathname.slice(1);
				if (caseSensitivePath === encryptionSecret && encryptionSecret !== '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改') {//快速订阅
					const params = new URLSearchParams(url.search);
					params.set('token', await MD5MD5(host + userID));
					return new Response('重定向中...', { status: 302, headers: { 'Location': `/sub?${params.toString()}` } });
				} else if (requestPath === 'login') {//处理登录页面和登录请求
					const cookies = request.headers.get('Cookie') || '';
					const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
					if (authCookie == await MD5MD5(UA + encryptionSecret + adminPassword)) return new Response('重定向中...', { status: 302, headers: { 'Location': '/admin' } });
					if (request.method === 'POST') {
						const formData = await request.text();
						const params = new URLSearchParams(formData);
						const inputPassword = params.get('password');
						if (inputPassword === (typeof adminPassword === 'string' ? adminPassword.replace(/[\r\n]/g, '') : adminPassword)) {
							// 密码正确，设置cookie并返回成功标记
							const response = new Response(JSON.stringify({ success: true }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							response.headers.set('Set-Cookie', `auth=${await MD5MD5(UA + encryptionSecret + adminPassword)}; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Lax`);
							return response;
						}
					}
					return fetch(PAGES_SITE_URL + '/login');
				} else if (requestPath === 'admin' || requestPath.startsWith('admin/')) {//验证cookie后响应管理页面
					const cookies = request.headers.get('Cookie') || '';
					const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
					// 没有cookie或cookie错误，跳转到/login页面
					if (!authCookie || authCookie !== await MD5MD5(UA + encryptionSecret + adminPassword)) return new Response('重定向中...', { status: 302, headers: { 'Location': '/login' } });
					if (requestPath === 'admin/log.json') {// 读取日志内容
						const readLogContent = await env.KV.get('log.json') || '[]';
						return new Response(readLogContent, { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					} else if (caseSensitivePath === 'admin/getCloudflareUsage') {// 查询请求量
						try {
							const Usage_JSON = await getCloudflareUsage(url.searchParams.get('Email'), url.searchParams.get('GlobalAPIKey'), url.searchParams.get('AccountID'), url.searchParams.get('APIToken'));
							return new Response(JSON.stringify(Usage_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
						} catch (err) {
							const errorResponse = { msg: '查询请求量失败，失败原因：' + err.message, error: err.message };
							return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						}
					} else if (caseSensitivePath === 'admin/getADDAPI') {// 验证优选API
						if (url.searchParams.get('url')) {
							const bestIPUrlsToVerify = url.searchParams.get('url');
							try {
								new URL(bestIPUrlsToVerify);
								const bestIPApiContent = await fetchBestIPApi([bestIPUrlsToVerify], url.searchParams.get('port') || '443', identityHeader);
								let bestIPApiResults = bestIPApiContent[0].length > 0 ? bestIPApiContent[0] : bestIPApiContent[1];
								bestIPApiResults = bestIPApiResults.map(item => item.replace(/#(.+)$/, (_, remark) => '#' + decodeURIComponent(remark)));
								return new Response(JSON.stringify({ success: true, data: bestIPApiResults }, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (err) {
								const errorResponse = { msg: '验证优选API失败，失败原因：' + err.message, error: err.message };
								return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						}
						return new Response(JSON.stringify({ success: false, data: [] }, null, 2), { status: 403, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					} else if (requestPath === 'admin/check') {// 代理检查
						const proxyProtocol = ['socks5', 'http', 'https', 'turn', 'sstp'].find(type => url.searchParams.has(type)) || null;
						if (!proxyProtocol) return new Response(JSON.stringify({ error: '缺少代理参数' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						const proxyParams = url.searchParams.get(proxyProtocol);
						const startTime = Date.now();
						let detectProxyResponse;
						try {
							const checkParsed = await getSocks5Account(proxyParams, getProxyDefaultPort(proxyProtocol));
							const { username, password, hostname, port } = checkParsed;
							const fullProxyParams = username && password ? `${username}:${password}@${hostname}:${port}` : `${hostname}:${port}`;
							try {
								const detectHost = 'cloudflare.com', detectPort = 443, encoder = new TextEncoder(), decoder = new TextDecoder();
								const tcpConnect = createRequestTcpConnector(request);
								let tcpSocket = null, tlsSocket = null;
								try {
									tcpSocket = proxyProtocol === 'socks5'
										? await socks5Connect(detectHost, detectPort, new Uint8Array(0), tcpConnect, checkParsed)
										: proxyProtocol === 'turn'
											? await turnConnect(checkParsed, detectHost, detectPort, tcpConnect)
											: proxyProtocol === 'sstp'
												? await sstpConnect(checkParsed, detectHost, detectPort, tcpConnect)
												: (proxyProtocol === 'https' && isIPHostname(hostname)
													? await httpsConnect(detectHost, detectPort, new Uint8Array(0), tcpConnect, checkParsed)
													: await httpConnect(detectHost, detectPort, new Uint8Array(0), proxyProtocol === 'https', tcpConnect, checkParsed));
									if (!tcpSocket) throw new Error('无法连接到代理服务器');
									tlsSocket = new TlsClient(tcpSocket, { serverName: detectHost, insecure: true });
									await tlsSocket.handshake();
									await tlsSocket.write(encoder.encode(`GET /cdn-cgi/trace HTTP/1.1\r\nHost: ${detectHost}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n`));
									let responseBuffer = new Uint8Array(0), headerEndIndex = -1, contentLength = null, chunked = false;
									const maxResponseBytes = 64 * 1024;
									while (responseBuffer.length < maxResponseBytes) {
										const value = await tlsSocket.read();
										if (!value) break;
										if (value.byteLength === 0) continue;
										responseBuffer = concatByteChunks(responseBuffer, value);
										if (headerEndIndex === -1) {
											const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
											if (crlfcrlf !== -1) {
												headerEndIndex = crlfcrlf + 4;
												const headers = decoder.decode(responseBuffer.slice(0, headerEndIndex));
												const statusLine = headers.split('\r\n')[0] || '';
												const statusMatch = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
												const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
												if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`代理检测请求失败: ${statusLine || '无效响应'}`);
												const lengthMatch = headers.match(/\r\nContent-Length:\s*(\d+)/i);
												if (lengthMatch) contentLength = parseInt(lengthMatch[1], 10);
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
									detectProxyResponse = { success: true, proxy: proxyProtocol + "://" + fullProxyParams, ip, loc, responseTime: Date.now() - startTime };
								} finally {
									try { tlsSocket ? tlsSocket.close() : await tcpSocket?.close?.() } catch (e) { }
								}
							} catch (error) {
								detectProxyResponse = { success: false, error: error.message, proxy: proxyProtocol + "://" + fullProxyParams, responseTime: Date.now() - startTime };
							}
						} catch (err) {
							detectProxyResponse = { success: false, error: err.message, proxy: proxyProtocol + "://" + proxyParams, responseTime: Date.now() - startTime };
						}
						return new Response(JSON.stringify(detectProxyResponse, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					}

					config_JSON = await loadConfig(env, host, userID, UA);

					if (requestPath === 'admin/init') {// 重置配置为默认值
						try {
							config_JSON = await loadConfig(env, host, userID, UA, true);
							ctx.waitUntil(writeRequestLog(env, request, clientIP, 'Init_Config', config_JSON));
							config_JSON.init = '配置已重置为默认值';
							return new Response(JSON.stringify(toLegacyConfig(config_JSON), null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						} catch (err) {
							const errorResponse = { msg: '配置重置失败，失败原因：' + err.message, error: err.message };
							return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						}
					} else if (request.method === 'POST') {// 处理 KV 操作（POST 请求）
						if (requestPath === 'admin/config.json') { // 保存config.json配置
							try {
								const newConfig = await request.json();
								migrateConfigKeysDeep(newConfig, CONFIG_KEY_CN_TO_EN);
								// 验证配置完整性
								if (!newConfig.UUID || !newConfig.HOST) return new Response(JSON.stringify({ error: '配置不完整' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });

								// 保存到 KV
								await env.KV.put('config.json', JSON.stringify(newConfig, null, 2));
								ctx.waitUntil(writeRequestLog(env, request, clientIP, 'Save_Config', config_JSON));
								return new Response(JSON.stringify({ success: true, message: '配置已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (error) {
								console.error('保存配置失败:', error);
								return new Response(JSON.stringify({ error: '保存配置失败: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						} else if (requestPath === 'admin/cf.json') { // 保存cf.json配置
							try {
								const newConfig = await request.json();
								const CF_JSON = { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null, UsageAPI: null };
								if (!newConfig.init || newConfig.init !== true) {
									if (newConfig.Email && newConfig.GlobalAPIKey) {
										CF_JSON.Email = newConfig.Email;
										CF_JSON.GlobalAPIKey = newConfig.GlobalAPIKey;
									} else if (newConfig.AccountID && newConfig.APIToken) {
										CF_JSON.AccountID = newConfig.AccountID;
										CF_JSON.APIToken = newConfig.APIToken;
									} else if (newConfig.UsageAPI) {
										CF_JSON.UsageAPI = newConfig.UsageAPI;
									} else {
										return new Response(JSON.stringify({ error: '配置不完整' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
									}
								}

								// 保存到 KV
								await env.KV.put('cf.json', JSON.stringify(CF_JSON, null, 2));
								ctx.waitUntil(writeRequestLog(env, request, clientIP, 'Save_Config', config_JSON));
								return new Response(JSON.stringify({ success: true, message: '配置已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (error) {
								console.error('保存配置失败:', error);
								return new Response(JSON.stringify({ error: '保存配置失败: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						} else if (requestPath === 'admin/tg.json') { // 保存tg.json配置
							try {
								const newConfig = await request.json();
								if (newConfig.init && newConfig.init === true) {
									const TG_JSON = { BotToken: null, ChatID: null };
									await env.KV.put('tg.json', JSON.stringify(TG_JSON, null, 2));
								} else {
									if (!newConfig.BotToken || !newConfig.ChatID) return new Response(JSON.stringify({ error: '配置不完整' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
									await env.KV.put('tg.json', JSON.stringify(newConfig, null, 2));
								}
								ctx.waitUntil(writeRequestLog(env, request, clientIP, 'Save_Config', config_JSON));
								return new Response(JSON.stringify({ success: true, message: '配置已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (error) {
								console.error('保存配置失败:', error);
								return new Response(JSON.stringify({ error: '保存配置失败: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						} else if (caseSensitivePath === 'admin/ADD.txt') { // 保存自定义优选IP
							try {
								const customIPs = await request.text();
								await env.KV.put('ADD.txt', customIPs);// 保存到 KV
								ctx.waitUntil(writeRequestLog(env, request, clientIP, 'Save_Custom_IPs', config_JSON));
								return new Response(JSON.stringify({ success: true, message: '自定义IP已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (error) {
								console.error('保存自定义IP失败:', error);
								return new Response(JSON.stringify({ error: '保存自定义IP失败: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						} else return new Response(JSON.stringify({ error: '不支持的POST请求路径' }), { status: 404, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					} else if (requestPath === 'admin/config.json') {// 处理 admin/config.json 请求，返回JSON（转回管理页使用的中文键）
						return new Response(JSON.stringify(toLegacyConfig(config_JSON), null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
					} else if (caseSensitivePath === 'admin/ADD.txt') {// 处理 admin/ADD.txt 请求，返回本地优选IP
						let localBestIP = await env.KV.get('ADD.txt') || 'null';
						if (localBestIP == 'null') localBestIP = (await generateRandomIPs(request, config_JSON.bestSubGen.localIPPool.randomCount, config_JSON.bestSubGen.localIPPool.fixedPort))[1];
						return new Response(localBestIP, { status: 200, headers: { 'Content-Type': 'text/plain;charset=utf-8', 'asn': request.cf.asn } });
					} else if (requestPath === 'admin/cf.json') {// CF配置文件
						return new Response(JSON.stringify(request.cf, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					}

					ctx.waitUntil(writeRequestLog(env, request, clientIP, 'Admin_Login', config_JSON));
					return fetch(PAGES_SITE_URL + '/admin' + url.search);
				} else if (requestPath === 'logout' || uuidRegex.test(requestPath)) {//清除cookie并跳转到登录页面
					const response = new Response('重定向中...', { status: 302, headers: { 'Location': '/login' } });
					response.headers.set('Set-Cookie', 'auth=; Path=/; Max-Age=0; HttpOnly');
					return response;
				} else if (requestPath === 'sub') {//处理订阅请求
					const subToken = await MD5MD5(host + userID), asBestSubGenerator = ['1', 'true'].includes(env.BEST_SUB) && url.searchParams.get('host') === 'example.com' && url.searchParams.get('uuid') === '00000000-0000-4000-8000-000000000000' && UA.toLowerCase().includes('tunnel (https://github.com/' + BRAND_OWNER + '/edge');
					const requestToken = url.searchParams.get('token');
					const clientRequestsSub = requestToken === subToken;
					const currentDayIndex = Math.floor(Date.now() / 86400000);
					const subBackendTokenSeed = base64SecretEncode(subToken, userID);
					const [todaySubBackendToken, yesterdaySubBackendToken] = await Promise.all([
						MD5MD5(subBackendTokenSeed + currentDayIndex),
						MD5MD5(subBackendTokenSeed + (currentDayIndex - 1)),
					]);
					const subBackendFetchSub = requestToken === todaySubBackendToken || requestToken === yesterdaySubBackendToken;
					if (clientRequestsSub || subBackendFetchSub || asBestSubGenerator) {
						config_JSON = await loadConfig(env, host, userID, UA);
						if (asBestSubGenerator) ctx.waitUntil(writeRequestLog(env, request, clientIP, 'Get_Best_SUB', config_JSON, false));
						else ctx.waitUntil(writeRequestLog(env, request, clientIP, 'Get_SUB', config_JSON));
						const ua = UA.toLowerCase();
						const responseHeaders = {
							"content-type": "text/plain; charset=utf-8",
							"Profile-Update-Interval": config_JSON.bestSubGen.SUBUpdateTime,
							"Profile-web-page-url": url.protocol + '//' + url.host + '/admin',
							"Cache-Control": "no-store",
						};
						if (config_JSON.CF.Usage.success) {
							const pagesSum = config_JSON.CF.Usage.pages;
							const workersSum = config_JSON.CF.Usage.workers;
							const total = Number.isFinite(config_JSON.CF.Usage.max) ? (config_JSON.CF.Usage.max / 1000) * 1024 : 1024 * 100;
							responseHeaders["Subscription-Userinfo"] = `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=4102329600`; // 2099-12-31 到期时间
						}
						const isSubConverterRequest = url.searchParams.has('b64') || url.searchParams.has('base64') || request.headers.get('subconverter-request') || request.headers.get('subconverter-version') || ua.includes('subconverter') || ua.includes(('CF-Workers-SUB').toLowerCase()) || asBestSubGenerator;
						const subType = isSubConverterRequest
							? 'mixed'
							: url.searchParams.has('target')
								? url.searchParams.get('target')
								: url.searchParams.has('clash') || ua.includes('clash') || ua.includes('meta') || ua.includes('mihomo')
									? 'clash'
									: url.searchParams.has('sb') || url.searchParams.has('singbox') || ua.includes('singbox') || ua.includes('sing-box')
										? 'singbox'
										: url.searchParams.has('surge') || ua.includes('surge')
											? 'surge&ver=4'
											: url.searchParams.has('quanx') || ua.includes('quantumult')
												? 'quanx'
												: url.searchParams.has('loon') || ua.includes('loon')
													? 'loon'
													: 'mixed';

						if (!ua.includes('mozilla')) responseHeaders["Content-Disposition"] = `attachment; filename*=utf-8''${encodeURIComponent(config_JSON.bestSubGen.SUBNAME)}`;
						const protocolType = ((url.searchParams.has('surge') || ua.includes('surge')) && config_JSON.protocolType !== 'ss') ? 'trojan' : config_JSON.protocolType;
						let subContent = '';
						if (subType === 'mixed') {
							const tlsFragmentParams = config_JSON.tlsFragment == 'Shadowrocket' ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : config_JSON.tlsFragment == 'Happ' ? `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
							let fullBestIP = [], otherNodeLinks = '', proxyIPPool = [];

							if (!url.searchParams.has('sub') && config_JSON.bestSubGen.local) { // 本地生成订阅
								const fullBestIPList = config_JSON.bestSubGen.localIPPool.randomIP ? (
									await generateRandomIPs(request, config_JSON.bestSubGen.localIPPool.randomCount, config_JSON.bestSubGen.localIPPool.fixedPort)
								)[0] : await env.KV.get('ADD.txt') ? await ensureArray(await env.KV.get('ADD.txt')) : (
									await generateRandomIPs(request, config_JSON.bestSubGen.localIPPool.randomCount, config_JSON.bestSubGen.localIPPool.fixedPort)
								)[0];
								const bestIPApi = [], bestIP = [], otherNodes = [];
								for (const element of fullBestIPList) {
									if (element.toLowerCase().startsWith('sub://')) {
										bestIPApi.push(element);
									} else {
										const remarkPos = element.indexOf('#');
										const addressPart = remarkPos > -1 ? element.slice(0, remarkPos) : element;
										const remarkPart = remarkPos > -1 ? element.slice(remarkPos) : '';
										const subMatch = element.match(/sub\s*=\s*([^\s&#]+)/i);
										if (subMatch && subMatch[1].trim().includes('.')) {
											const bestIPAsProxyIP = element.toLowerCase().includes('proxyip=true');
											if (bestIPAsProxyIP) bestIPApi.push('sub://' + subMatch[1].trim() + "?proxyip=true" + (element.includes('#') ? ('#' + element.split('#')[1]) : ''));
											else bestIPApi.push('sub://' + subMatch[1].trim() + (element.includes('#') ? ('#' + element.split('#')[1]) : ''));
										} else if (addressPart.toLowerCase().startsWith('https://')) {
											bestIPApi.push(element);
										} else if (addressPart.toLowerCase().includes('://')) {
											if (element.includes('#')) {
												const splitAddrRemark = element.split('#');
												otherNodes.push(splitAddrRemark[0] + '#' + encodeURIComponent(decodeURIComponent(splitAddrRemark[1])));
											} else otherNodes.push(element);
										} else {
											if (addressPart.includes('*')) {
												bestIP.push(replaceAsterisks(addressPart) + remarkPart);
											} else bestIP.push(element);
										}
									}
								}
								const bestIPApiContent = await fetchBestIPApi(bestIPApi, '443', identityHeader);
								const mergeOtherNodesArray = [...new Set(otherNodes.concat(bestIPApiContent[1]))];
								otherNodeLinks = mergeOtherNodesArray.length > 0 ? mergeOtherNodesArray.join('\n') + '\n' : '';
								const bestIPApiResults = bestIPApiContent[0];
								proxyIPPool = bestIPApiContent[3] || [];
								fullBestIP = [...new Set(bestIP.concat(bestIPApiResults))];
							} else { // 优选订阅生成器
								let bestSubGeneratorHost = url.searchParams.get('sub') || config_JSON.bestSubGen.SUB;
								const [bestGenIPList, bestGenOtherNodes] = await fetchBestSubGeneratorData(bestSubGeneratorHost, identityHeader);
								fullBestIP = fullBestIP.concat(bestGenIPList);
								otherNodeLinks += bestGenOtherNodes;
							}
							const echLinkParams = config_JSON.ECH ? `&ech=${encodeURIComponent((config_JSON.ECHConfig.SNI ? config_JSON.ECHConfig.SNI + '+' : '') + config_JSON.ECHConfig.DNS)}` : '';
							const isLoonOrSurge = ua.includes('loon') || ua.includes('surge');
							const { type: transport, pathFieldName, hostFieldName } = getTransportConfig(config_JSON);
							subContent = otherNodeLinks + fullBestIP.map(originalAddress => {
								// 统一正则: 匹配 域名/IPv4/IPv6地址 + 可选端口 + 可选备注
								// 示例:
								//   - 域名: hj.xmm1993.top:2096#备注 或 example.com
								//   - IPv4: 166.0.188.128:443#Los Angeles 或 166.0.188.128
								//   - IPv6: [2606:4700::]:443#CMCC 或 [2606:4700::]
								const regex = /^(\[[\da-fA-F:]+\]|[\d.]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(?::(\d+))?(?:#(.+))?$/;
								const match = originalAddress.match(regex);

								let nodeAddress, nodePort = "443", nodeRemark;

								if (match) {
									nodeAddress = match[1];  // IP地址或域名(可能带方括号)
									nodePort = match[2] ? match[2] : '443';  // 端口默认443，SS noTLS在生成链接时再映射
									nodeRemark = match[3] || nodeAddress;  // 备注,默认为地址本身
								} else {
									// 不规范的格式，跳过处理返回null
									console.warn(`[订阅内容] 不规范的IP格式已忽略: ${originalAddress}`);
									return null;
								}

								let fullNodePath = config_JSON.fullNodePath;

								const chainProxyMatch = nodeRemark.match(/\$(socks5|http|https|turn|sstp):\/\/([^#\s]+)/i);
								if (chainProxyMatch) {
									try {
										const proxyProtocol = chainProxyMatch[1].toLowerCase(), proxyParams = chainProxyMatch[2];
										const chainProxyData = { type: proxyProtocol, ...getSocks5Account(proxyParams, getProxyDefaultPort(proxyProtocol)) };
										fullNodePath = `/video/${base64SecretEncode(JSON.stringify(chainProxyData), userID) + (config_JSON.enable0RTT ? '?ed=2560' : '')}`;
										nodeRemark = nodeRemark.replace(chainProxyMatch[0], '').trim() || nodeAddress;
									} catch (error) {
										console.warn(`[订阅内容] 链式代理解析失败，已忽略该指令: ${chainProxyMatch[0]} (${error && error.message ? error.message : error})`);
									}
								} else if (proxyIPPool.length > 0) {
									const matchedProxyIP = proxyIPPool.find(p => p.includes(nodeAddress));
									if (matchedProxyIP) fullNodePath = (`${config_JSON.PATH}/proxyip=${matchedProxyIP}`).replace(/\/\//g, '/') + (config_JSON.enable0RTT ? '?ed=2560' : '');
								}
								if (isLoonOrSurge) fullNodePath = fullNodePath.replace(/,/g, '%2C');

								if (protocolType === 'ss' && !asBestSubGenerator) {
									if (!config_JSON.SS.TLS) {
										const TLS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
										const NO_TLS_PORTS = [80, 2052, 2082, 2086, 2095, 8080];
										nodePort = String(NO_TLS_PORTS[TLS_PORTS.indexOf(Number(nodePort))] ?? nodePort);
									}
									fullNodePath = (fullNodePath.includes('?') ? fullNodePath.replace('?', '?enc=' + config_JSON.SS.encryptionMethod + '&') : (fullNodePath + '?enc=' + config_JSON.SS.encryptionMethod)).replace(/([=,])/g, '\\$1');
									if (!isSubConverterRequest) fullNodePath = fullNodePath + ';mux=0';
									return `${protocolType}://${btoa(config_JSON.SS.encryptionMethod + ':00000000-0000-4000-8000-000000000000')}@${nodeAddress}:${nodePort}?plugin=v2${encodeURIComponent('ray-plugin;mode=websocket;host=example.com;path=' + (config_JSON.randomPath ? randomPath(fullNodePath) : fullNodePath) + (config_JSON.SS.TLS ? ';tls' : '')) + echLinkParams + tlsFragmentParams}#${encodeURIComponent(nodeRemark)}`;
								} else {
									const transportPathValue = getTransportPathValue(config_JSON, fullNodePath, asBestSubGenerator);
									return `${protocolType}://00000000-0000-4000-8000-000000000000@${nodeAddress}:${nodePort}?security=tls&type=${transport + echLinkParams}&${hostFieldName}=example.com&fp=${config_JSON.Fingerprint}&sni=example.com&${pathFieldName}=${encodeURIComponent(transportPathValue) + tlsFragmentParams}&encryption=none&alpn=${encodeURIComponent(config_JSON.ALPN)}#${encodeURIComponent(nodeRemark)}`;
								}
							}).filter(item => item !== null).join('\n');
						} else { // 订阅转换
							const subConverterUrl = `${config_JSON.subConverterConfig.SUBAPI}/sub?target=${subType}&url=${encodeURIComponent(url.protocol + '//' + url.host + '/sub?target=mixed&token=' + todaySubBackendToken + '&cnIspCode=' + detectISP(request) + (url.searchParams.has('sub') && url.searchParams.get('sub') != '' ? `&sub=${url.searchParams.get('sub')}` : ''))}&config=${encodeURIComponent(config_JSON.subConverterConfig.SUBCONFIG)}&emoji=${config_JSON.subConverterConfig.SUBEMOJI}&list=${config_JSON.subConverterConfig.SUBLIST}&scv=${config_JSON.skipCertVerify}&xudp=${config_JSON.subConverterConfig.XUDP}&udp=${config_JSON.subConverterConfig.UDP}&tls13=${config_JSON.subConverterConfig.TLS13}&append_type=${config_JSON.subConverterConfig.APPEND_TYPE}&sort=${config_JSON.subConverterConfig.SORT}&expand=${config_JSON.subConverterConfig.EXPAND}`;
							try {
								const response = await fetch(subConverterUrl, { headers: { 'User-Agent': 'Subconverter for ' + subType + ' edge' + 'tunnel (https://github.com/' + BRAND_OWNER + '/edge' + 'tunnel) Uid/0x' + identityHeader + ' Version/' + EDT_VERSION } });
								if (response.ok) {
									subContent = await response.text();
									if (url.searchParams.has('surge') || ua.includes('surge')) subContent = applySurgePatch(subContent, url.protocol + '//' + url.host + '/sub?token=' + subToken + '&surge', config_JSON);
								} else return new Response('订阅转换后端异常：' + response.statusText, { status: response.status });
							} catch (error) {
								return new Response('订阅转换后端异常：' + error.message, { status: 403 });
							}
						}

						if (!ua.includes('subconverter') && clientRequestsSub) {
							const shuffledHosts = [...config_JSON.HOSTS].sort(() => Math.random() - 0.5);
							let hostReplaceCount = 0, currentRandomHost = null;
							subContent = subContent
								.replace(/00000000-0000-4000-8000-000000000000/g, config_JSON.UUID)
								.replace(/MDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDAw/g, btoa(config_JSON.UUID))
								.replace(/example\.com/g, () => {
									if (hostReplaceCount % 2 === 0) {
										const originalHost = shuffledHosts[Math.floor(hostReplaceCount / 2) % shuffledHosts.length];
										currentRandomHost = replaceAsterisks(originalHost);
									}
									hostReplaceCount++;
									return currentRandomHost;
								});
						}

						if (subType === 'mixed' && (!ua.includes('mozilla') || url.searchParams.has('b64') || url.searchParams.has('base64'))) subContent = btoa(subContent);

						if (subType === 'singbox') {
							subContent = await applySingboxPatch(subContent, config_JSON);
							responseHeaders["content-type"] = 'application/json; charset=utf-8';
						} else if (subType === 'clash') {
							subContent = applyClashPatch(subContent, config_JSON);
							responseHeaders["content-type"] = 'application/x-yaml; charset=utf-8';
						}
						return new Response(subContent, { status: 200, headers: responseHeaders });
					}
				} else if (requestPath === 'locations') {//反代locations列表
					const cookies = request.headers.get('Cookie') || '';
					const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
					if (authCookie && authCookie == await MD5MD5(UA + encryptionSecret + adminPassword)) return fetch(new Request('https://speed.cloudflare.com/locations', { headers: { 'Referer': 'https://speed.cloudflare.com/' } }));
				} else if (requestPath === 'robots.txt') return new Response('User-agent: *\nDisallow: /', { status: 200, headers: { 'Content-Type': 'text/plain; charset=UTF-8' } });
			} else if (!envUUID) return fetch(PAGES_SITE_URL + '/noKV').then(r => { const headers = new Headers(r.headers); headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate'); headers.set('Pragma', 'no-cache'); headers.set('Expires', '0'); return new Response(r.body, { status: 404, statusText: r.statusText, headers }) });
		}

		let fakePageURL = env.URL || 'nginx';
		if (fakePageURL && fakePageURL !== 'nginx' && fakePageURL !== '1101') {
			fakePageURL = fakePageURL.trim().replace(/\/$/, '');
			if (!fakePageURL.match(/^https?:\/\//i)) fakePageURL = 'https://' + fakePageURL;
			if (fakePageURL.toLowerCase().startsWith('http://')) fakePageURL = 'https://' + fakePageURL.substring(7);
			try { const u = new URL(fakePageURL); fakePageURL = u.protocol + '//' + u.host } catch (e) { fakePageURL = 'nginx' }
		}
		if (fakePageURL === '1101') return new Response(await html1101(url.host, clientIP), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
		try {
			const proxyURL = new URL(fakePageURL), newHeaders = new Headers(request.headers);
			newHeaders.set('Host', proxyURL.host);
			newHeaders.set('Referer', proxyURL.origin);
			newHeaders.set('Origin', proxyURL.origin);
			if (!newHeaders.has('User-Agent') && UA && UA !== 'null') newHeaders.set('User-Agent', UA);
			const proxyResponse = await fetch(proxyURL.origin + url.pathname + url.search, { method: request.method, headers: newHeaders, body: request.body, cf: request.cf });
			const contentType = proxyResponse.headers.get('content-type') || '';
			// 只处理文本类型的响应
			if (/text|javascript|json|xml/.test(contentType)) {
				const responseContent = (await proxyResponse.text()).replaceAll(proxyURL.host, url.host);
				return new Response(responseContent, { status: proxyResponse.status, headers: { ...Object.fromEntries(proxyResponse.headers), 'Cache-Control': 'no-store' } });
			}
			return proxyResponse;
		} catch (error) { }
		return new Response(await nginx(), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
	}
};
///////////////////////////////////////////////////////////////////////xHTTP 传输层（HPACK padding / 首包识别 / UDP 桥）/////////////////////////////////////////////
const HPACK_HUFFMAN_CODE_LENGTHS = [
	13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
	28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
	6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
	5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
	13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
	15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
	6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
	20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
	24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
	22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
	21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
	26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
	19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
	20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
	26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
	30
];

function getIdentity(yourUUID) {
	return [yourUUID.slice(1, 7), '_' + yourUUID.slice(25, 31)];
}

function calcHpackHuffmanByteLength(str) {
	const bytes = new TextEncoder().encode(str);
	let totalBits = 0;
	for (let i = 0; i < bytes.length; i++) {
		totalBits += HPACK_HUFFMAN_CODE_LENGTHS[bytes[i]];
	}
	return Math.ceil(totalBits / 8);
}

function extractXhttpPaddingValue(request, identityHeader, identityKey) {
	const headerValue = request.headers.get(identityHeader);
	if (headerValue) {
		try {
			const parseUrl = new URL(headerValue, 'https://x.invalid');
			const queryValue = parseUrl.searchParams.get(identityKey);
			if (queryValue) return queryValue;
		} catch (e) { }
		return headerValue;
	}
	const requestUrl = new URL(request.url);
	return requestUrl.searchParams.get(identityKey) || '';
}

function verifyXhttpPadding(request, identityHeader, identityKey) {
	const paddingValue = extractXhttpPaddingValue(request, identityHeader, identityKey);
	if (!paddingValue) return true;
	const huffmanByteLen = calcHpackHuffmanByteLength(paddingValue);
	return huffmanByteLen >= 98 && huffmanByteLen <= 1002;
}

const XHTTP_BASE62_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
function generateXhttpPaddingString(length) {
	const charsetLen = XHTTP_BASE62_ALPHABET.length;
	let result = '';
	for (let i = 0; i < length; i++) {
		result += XHTTP_BASE62_ALPHABET[Math.floor(Math.random() * charsetLen)];
	}
	return result;
}

// xHTTP 入口：校验 padding 标识，读首包后交给协议解析与 TCP/UDP 转发核心
async function handleXhttpRequest(request, yourUUID, proxyCtx = {}) {
	if (!request.body) return new Response('Bad Request', { status: 400 });
	const [identityHeader, identityKey] = getIdentity(yourUUID);
	if (!verifyXhttpPadding(request, identityHeader, identityKey)) return new Response('Bad Request', { status: 400 });
	const reader = request.body.getReader();
	const firstPacket = await readXhttpFirstPacket(reader, yourUUID);
	if (!firstPacket) {
		try { reader.releaseLock() } catch (e) { }
		return new Response('Invalid request', { status: 400 });
	}
	if (isSpeedTestSite(firstPacket.hostname) && proxyCtx.proxyType === null) {
		try { reader.releaseLock() } catch (e) { }
		return new Response(buildLocal204Response(firstPacket.respHeader), {
			status: 200,
			headers: {
				'Content-Type': 'application/octet-stream',
				'X-Accel-Buffering': 'no',
				'Cache-Control': 'no-store'
			}
		});
	}
	if (firstPacket.isUDP && firstPacket.protocol !== 'trojan' && firstPacket.port !== 53) {
		try { reader.releaseLock() } catch (e) { }
		return new Response('UDP is not supported', { status: 400 });
	}

	const responseHeaders = new Headers({
		'Content-Type': 'application/octet-stream',
		'X-Accel-Buffering': 'no',
		'Cache-Control': 'no-store'
	});

	try {
		const responseUrl = new URL('https://x.invalid/');
		responseUrl.searchParams.set(identityKey, generateXhttpPaddingString(100 + Math.floor(Math.random() * 901)));
		responseHeaders.set(identityHeader, responseUrl.toString());
	} catch (e) { }

	if (firstPacket.isUDP) return handleXhttpUdpRequest(firstPacket, reader, request, proxyCtx, responseHeaders);

	try { reader.releaseLock() } catch (e) { }

	const remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null, downlinkDrain: Promise.resolve() };
	const abortController = new AbortController();
	let cleaned = false;
	const cleanup = (reason) => {
		if (cleaned) return;
		cleaned = true;
		try { abortController.abort(reason) } catch (e) { }
		invalidateTcpGeneration(remoteConnWrapper);
	};

	const placeholderWs = { readyState: WebSocket.OPEN };

	let socket;
	try {
		socket = await forwardataTCP(firstPacket.hostname, firstPacket.port, firstPacket.rawData, placeholderWs, firstPacket.respHeader, remoteConnWrapper, yourUUID, request, proxyCtx, firstPacket.protocol === 'trojan', firstPacket.rawData, true);
	} catch (err) {
		log(`[叉HTTP-Pipe] 连接失败: ${err?.message || err}`);
		cleanup(err);
		return new Response('bad gateway', { status: 502 });
	}
	if (!socket) {
		cleanup(new Error('socket is null'));
		return new Response('bad gateway', { status: 502 });
	}

	const uplinkPromise = (async () => {
		const uplinkCoalescer = createUplinkCoalesceStream();
		const pipePromise = uplinkCoalescer.readable.pipeTo(socket.writable, { signal: abortController.signal });
		void pipePromise.catch(cleanup);
		const uplinkReader = request.body.getReader();
		const cancelUplinkReader = () => {
			try { uplinkReader.cancel(abortController.signal.reason).catch(() => { }); } catch (e) { }
		};
		abortController.signal.addEventListener('abort', cancelUplinkReader, { once: true });
		try {
			try {
				while (true) {
					const { done, value } = await uplinkReader.read();
					if (done) break;
					if (value?.byteLength) await uplinkCoalescer.write(value);
				}
			} finally {
				abortController.signal.removeEventListener('abort', cancelUplinkReader);
				try { uplinkReader.releaseLock() } catch (e) { }
			}
		} finally {
			try { await uplinkCoalescer.end() } catch (e) { }
		}
		await pipePromise;
	})();

	const responseStream = typeof IdentityTransformStream !== 'undefined'
		? new IdentityTransformStream()
		: new TransformStream();
	const downlinkPromise = (async () => {
		const writer = responseStream.writable.getWriter();
		try {
			if (effectiveByteLength(firstPacket.respHeader) > 0) await writer.write(firstPacket.respHeader);
		} catch (error) {
			try { await writer.abort(error) } catch (e) { }
			throw error;
		} finally {
			try { writer.releaseLock() } catch (e) { }
		}
		await socket.readable.pipeTo(responseStream.writable, { signal: abortController.signal });
	})();

	void uplinkPromise.catch(cleanup);
	void downlinkPromise.then(() => cleanup(), cleanup);
	void Promise.allSettled([uplinkPromise, downlinkPromise]);

	return new Response(responseStream.readable, { status: 200, headers: responseHeaders });
}

function handleXhttpUdpRequest(firstPacket, reader, request, proxyCtx, responseHeaders) {
	const trojanUdpCtx = { cache: new Uint8Array(0), proxyAddr: proxyCtx.trojanProxyAddr };
	return new Response(new ReadableStream({
		async start(controller) {
			let isClosed = false;
			let udpRespHeader = firstPacket.respHeader;
			const xhttpBridge = {
				readyState: WebSocket.OPEN,
				send(data) {
					if (isClosed) return;
					try {
						const chunk = data instanceof Uint8Array
							? data
							: data instanceof ArrayBuffer
								? new Uint8Array(data)
								: ArrayBuffer.isView(data)
									? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
									: new Uint8Array(data);
						controller.enqueue(chunk);
					} catch (e) {
						isClosed = true;
						this.readyState = WebSocket.CLOSED;
					}
				},
				close() {
					if (isClosed) return;
					isClosed = true;
					this.readyState = WebSocket.CLOSED;
					try { controller.close() } catch (e) { }
				}
			};
			let forwardFailed = false;
			try {
				if (firstPacket.protocol === 'trojan') {
					trojanUdpCtx.targetHost = firstPacket.hostname;
					trojanUdpCtx.targetPort = firstPacket.port;
					if (trojanUdpCtx.proxyAddr) await forwardTrojanUdp(firstPacket.rawData, xhttpBridge, trojanUdpCtx, request);
				}
				if (!(firstPacket.protocol === 'trojan' && trojanUdpCtx.proxyAddr) && firstPacket.rawData?.byteLength) {
					if (firstPacket.protocol === 'trojan') await forwardTrojanUdp(firstPacket.rawData, xhttpBridge, trojanUdpCtx, request);
					else await forwardataudp(firstPacket.rawData, xhttpBridge, udpRespHeader, request);
					udpRespHeader = null;
				}
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					if (!value || value.byteLength === 0) continue;
					if (firstPacket.protocol === 'trojan') await forwardTrojanUdp(value, xhttpBridge, trojanUdpCtx, request);
					else await forwardataudp(value, xhttpBridge, udpRespHeader, request);
					udpRespHeader = null;
				}
			} catch (err) {
				forwardFailed = true;
				log(`[叉HTTP转发] 处理失败: ${err?.message || err}`);
				closeSocketQuietly(xhttpBridge);
			} finally {
				const keepTrojanUdpProxyDownlink = !forwardFailed && firstPacket.protocol === 'trojan' && trojanUdpCtx.proxyAddr && trojanUdpCtx.proxySocket;
				if (!keepTrojanUdpProxyDownlink) {
					try { trojanUdpCtx.proxySocket?.close() } catch (e) { }
					closeSocketQuietly(xhttpBridge);
				}
				try { reader.releaseLock() } catch (e) { }
			}
		},
		cancel() {
			try { trojanUdpCtx.proxySocket?.close() } catch (e) { }
			try { reader.releaseLock() } catch (e) { }
		}
	}), { status: 200, headers: responseHeaders });
}

function effectiveByteLength(data) {
	if (!data) return 0;
	if (typeof data.byteLength === 'number') return data.byteLength;
	if (typeof data.length === 'number') return data.length;
	return 0;
}

function invalidateTcpGeneration(remoteConnWrapper) {
	if (!remoteConnWrapper) return;
	remoteConnWrapper.generation = (Number.isInteger(remoteConnWrapper.generation) ? remoteConnWrapper.generation : 0) + 1;
	const socket = remoteConnWrapper.socket;
	remoteConnWrapper.socket = null;
	remoteConnWrapper.downlinkController = null;
	remoteConnWrapper.downlinkDrain = Promise.resolve();
	try { socket?.close?.() } catch (e) { }
}

function beginTcpGeneration(remoteConnWrapper) {
	if (!Number.isInteger(remoteConnWrapper.generation)) remoteConnWrapper.generation = 0;
	const generation = ++remoteConnWrapper.generation;
	const previousSocket = remoteConnWrapper.socket;
	remoteConnWrapper.socket = null;
	const previousDownlink = remoteConnWrapper.downlinkController;
	remoteConnWrapper.downlinkController = null;
	const previousDrain = remoteConnWrapper.downlinkDrain || Promise.resolve();
	let currentDrain;
	try { currentDrain = previousDownlink?.stopAndFlush?.() || Promise.resolve() }
	catch (error) { currentDrain = Promise.reject(error) }
	const downlinkDrain = Promise.all([previousDrain, currentDrain]);
	// Installation awaits this promise; attach a handler immediately in case draining fails before dialing completes.
	downlinkDrain.catch(() => { });
	remoteConnWrapper.downlinkDrain = downlinkDrain;
	try { previousSocket?.close?.() } catch (e) { }
	return { generation, downlinkDrain };
}

async function readXhttpFirstPacket(reader, token) {
	const decoder = vlessTextDecoder;

	const tryParseVlessFirstPacket = (data) => {
		const length = data.byteLength;
		if (length < 18) return { status: 'need_more' };
		if (!uuidBytesMatch(data, 1, token)) return { status: 'invalid' };

		const optLen = data[17];
		const cmdIndex = 18 + optLen;
		if (length < cmdIndex + 1) return { status: 'need_more' };

		const cmd = data[cmdIndex];
		if (cmd !== 1 && cmd !== 2) return { status: 'invalid' };

		const portIndex = cmdIndex + 1;
		if (length < portIndex + 3) return { status: 'need_more' };

		const port = (data[portIndex] << 8) | data[portIndex + 1];
		const addressType = data[portIndex + 2];
		const addressIndex = portIndex + 3;
		let headerLen = -1;
		let hostname = '';

		if (addressType === 1) {
			if (length < addressIndex + 4) return { status: 'need_more' };
			hostname = `${data[addressIndex]}.${data[addressIndex + 1]}.${data[addressIndex + 2]}.${data[addressIndex + 3]}`;
			headerLen = addressIndex + 4;
		} else if (addressType === 2) {
			if (length < addressIndex + 1) return { status: 'need_more' };
			const domainLen = data[addressIndex];
			if (length < addressIndex + 1 + domainLen) return { status: 'need_more' };
			hostname = decoder.decode(data.subarray(addressIndex + 1, addressIndex + 1 + domainLen));
			headerLen = addressIndex + 1 + domainLen;
		} else if (addressType === 3) {
			if (length < addressIndex + 16) return { status: 'need_more' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = addressIndex + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			headerLen = addressIndex + 16;
		} else return { status: 'invalid' };

		if (!hostname) return { status: 'invalid' };

		return {
			status: 'ok',
			result: {
				protocol: 'vless',
				hostname,
				port,
				isUDP: cmd === 2,
				rawData: data.subarray(headerLen),
				respHeader: new Uint8Array([data[0], 0]),
				rawData: null,
			}
		};
	};

	const tryParseTrojanFirstPacket = (data) => {
		const passwordHash = sha224(token);
		const passwordHashBytes = new TextEncoder().encode(passwordHash);
		const length = data.byteLength;
		if (length < 58) return { status: 'need_more' };
		if (data[56] !== 0x0d || data[57] !== 0x0a) return { status: 'invalid' };
		for (let i = 0; i < 56; i++) {
			if (data[i] !== passwordHashBytes[i]) return { status: 'invalid' };
		}

		const socksStart = 58;
		if (length < socksStart + 2) return { status: 'need_more' };
		const cmd = data[socksStart];
		if (cmd !== 1 && cmd !== 3) return { status: 'invalid' };
		const isUDP = cmd === 3;

		const atype = data[socksStart + 1];
		let cursor = socksStart + 2;
		let hostname = '';

		if (atype === 1) {
			if (length < cursor + 4) return { status: 'need_more' };
			hostname = `${data[cursor]}.${data[cursor + 1]}.${data[cursor + 2]}.${data[cursor + 3]}`;
			cursor += 4;
		} else if (atype === 3) {
			if (length < cursor + 1) return { status: 'need_more' };
			const domainLen = data[cursor];
			if (length < cursor + 1 + domainLen) return { status: 'need_more' };
			hostname = decoder.decode(data.subarray(cursor + 1, cursor + 1 + domainLen));
			cursor += 1 + domainLen;
		} else if (atype === 4) {
			if (length < cursor + 16) return { status: 'need_more' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = cursor + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			cursor += 16;
		} else return { status: 'invalid' };

		if (!hostname) return { status: 'invalid' };
		if (length < cursor + 4) return { status: 'need_more' };

		const port = (data[cursor] << 8) | data[cursor + 1];
		if (data[cursor + 2] !== 0x0d || data[cursor + 3] !== 0x0a) return { status: 'invalid' };
		const dataOffset = cursor + 4;

		return {
			status: 'ok',
			result: {
				protocol: 'trojan',
				hostname,
				port,
				isUDP,
				rawData: data.subarray(dataOffset),
				rawData: data,
				respHeader: null,
			}
		};
	};

	let buffer = new Uint8Array(1024);
	let offset = 0;

	while (true) {
		const { value, done } = await reader.read();
		if (done) {
			if (offset === 0) return null;
			break;
		}

		const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
		if (offset + chunk.byteLength > buffer.byteLength) {
			const newBuffer = new Uint8Array(Math.max(buffer.byteLength * 2, offset + chunk.byteLength));
			newBuffer.set(buffer.subarray(0, offset));
			buffer = newBuffer;
		}

		buffer.set(chunk, offset);
		offset += chunk.byteLength;

		const currentData = buffer.subarray(0, offset);
		const trojanResult = tryParseTrojanFirstPacket(currentData);
		if (trojanResult.status === 'ok') return { ...trojanResult.result, reader };

		const vlessResult = tryParseVlessFirstPacket(currentData);
		if (vlessResult.status === 'ok') return { ...vlessResult.result, reader };

		if (trojanResult.status === 'invalid' && vlessResult.status === 'invalid') return null;
	}

	const finalData = buffer.subarray(0, offset);
	const finalTrojanResult = tryParseTrojanFirstPacket(finalData);
	if (finalTrojanResult.status === 'ok') return { ...finalTrojanResult.result, reader };
	const finalVlessResult = tryParseVlessFirstPacket(finalData);
	if (finalVlessResult.status === 'ok') return { ...finalVlessResult.result, reader };
	return null;
}
///////////////////////////////////////////////////////////////////////gRPC 传输层///////////////////////////////////////////////
// gRPC 入口：gRPC 帧内承载 Trojan/VLESS 首包，复用同一套转发核心
async function handleGrpcRequest(request, yourUUID, proxyCtx = {}) {
	if (!request.body) return new Response('Bad Request', { status: 400 });
	const reader = request.body.getReader();
	const remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null, downlinkDrain: Promise.resolve() };
	const invalidateRemoteConn = () => invalidateTcpGeneration(remoteConnWrapper);
	let isDnsQuery = false;
	const trojanUdpCtx = { cache: new Uint8Array(0), proxyAddr: proxyCtx.trojanProxyAddr };
	let isTrojan = null;
	let currentWriteSocket = null;
	let remoteWriter = null;
	let grpcUplinkWriteQueue = null;
	//log('[gRPC] 开始处理双向流');
	const grpcHeaders = new Headers({
		'Content-Type': 'application/grpc',
		'grpc-status': '0',
		'X-Accel-Buffering': 'no',
		'Cache-Control': 'no-store'
	});

	const downlinkCacheLimit = DOWNLINK_GRAIN_CHUNK_BYTES;
	const downlinkFlushInterval = 1;

	return new Response(new ReadableStream({
		async start(controller) {
			let isClosed = false;
			let sendQueue = [];
			let queueByteCount = 0;
			let flushTimer = null;
			let flushMicrotaskQueued = false;
			const grpcBridge = {
				readyState: WebSocket.OPEN,
				send(data) {
					if (isClosed) return;
					const chunk = data instanceof Uint8Array ? data : new Uint8Array(data);
					const lenBytesArr = [];
					let remaining = chunk.byteLength >>> 0;
					while (remaining > 127) {
						lenBytesArr.push((remaining & 0x7f) | 0x80);
						remaining >>>= 7;
					}
					lenBytesArr.push(remaining);
					const lenBytes = new Uint8Array(lenBytesArr);
					const protobufLen = 1 + lenBytes.length + chunk.byteLength;
					const frame = new Uint8Array(5 + protobufLen);
					frame[0] = 0;
					frame[1] = (protobufLen >>> 24) & 0xff;
					frame[2] = (protobufLen >>> 16) & 0xff;
					frame[3] = (protobufLen >>> 8) & 0xff;
					frame[4] = protobufLen & 0xff;
					frame[5] = 0x0a;
					frame.set(lenBytes, 6);
					frame.set(chunk, 6 + lenBytes.length);
					sendQueue.push(frame);
					queueByteCount += frame.byteLength;
					scheduleFlushSendQueue();
				},
				close() {
					if (this.readyState === WebSocket.CLOSED) return;
					flushSendQueue(true);
					isClosed = true;
					this.readyState = WebSocket.CLOSED;
					try { controller.close() } catch (e) { }
				}
			};

			const flushSendQueue = (force = false) => {
				flushMicrotaskQueued = false;
				if (flushTimer) {
					clearTimeout(flushTimer);
					flushTimer = null;
				}
				if ((!force && isClosed) || queueByteCount === 0) return;
				const out = new Uint8Array(queueByteCount);
				let offset = 0;
				for (const item of sendQueue) {
					out.set(item, offset);
					offset += item.byteLength;
				}
				sendQueue = [];
				queueByteCount = 0;
				try {
					controller.enqueue(out);
				} catch (e) {
					isClosed = true;
					grpcBridge.readyState = WebSocket.CLOSED;
				}
			};

			const scheduleFlushSendQueue = () => {
				if (queueByteCount >= downlinkCacheLimit) {
					flushSendQueue();
					return;
				}
				if (flushMicrotaskQueued || flushTimer) return;
				flushMicrotaskQueued = true;
				queueMicrotask(() => {
					flushMicrotaskQueued = false;
					if (isClosed || queueByteCount === 0 || flushTimer) return;
					flushTimer = setTimeout(flushSendQueue, downlinkFlushInterval);
				});
			};

			const closeConnection = () => {
				if (isClosed) return;
				grpcUplinkWriteQueue?.clear();
				invalidateRemoteConn();
				flushSendQueue(true);
				isClosed = true;
				grpcBridge.readyState = WebSocket.CLOSED;
				if (flushTimer) clearTimeout(flushTimer);
				if (remoteWriter) {
					try { remoteWriter.releaseLock() } catch (e) { }
					remoteWriter = null;
				}
				currentWriteSocket = null;
				try { reader.releaseLock() } catch (e) { }
				try { trojanUdpCtx.proxySocket?.close() } catch (e) { }
				try { controller.close() } catch (e) { }
			};

			const releaseRemoteWriter = () => {
				if (remoteWriter) {
					try { remoteWriter.releaseLock() } catch (e) { }
					remoteWriter = null;
				}
				currentWriteSocket = null;
			};

			const uplinkWriteQueue = grpcUplinkWriteQueue = createUplinkWriteQueue({
				getWriter: () => {
					const socket = remoteConnWrapper.socket;
					if (!socket) return null;
					if (socket !== currentWriteSocket) {
						releaseRemoteWriter();
						currentWriteSocket = socket;
						remoteWriter = socket.writable.getWriter();
					}
					return remoteWriter;
				},
				getConnectTask: () => remoteConnWrapper.connectingPromise,
				releaseWriter: releaseRemoteWriter,
				retryConnect: async () => {
					if (typeof remoteConnWrapper.retryConnect !== 'function') throw new Error('retry unavailable');
					await remoteConnWrapper.retryConnect();
				},
				closeConnection,
				queueName: 'gRPC上行'
			});

			const writeToRemote = async (payload, allowRetry = true) => {
				return uplinkWriteQueue.writeAndWait(payload, allowRetry);
			};

			let forwardFailed = false;
			try {
				let pending = new Uint8Array(0);
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					if (!value || value.byteLength === 0) continue;
					const currentChunk = value instanceof Uint8Array ? value : new Uint8Array(value);
					const merged = new Uint8Array(pending.length + currentChunk.length);
					merged.set(pending, 0);
					merged.set(currentChunk, pending.length);
					pending = merged;
					while (pending.byteLength >= 5) {
						const grpcLen = ((pending[1] << 24) >>> 0) | (pending[2] << 16) | (pending[3] << 8) | pending[4];
						const frameSize = 5 + grpcLen;
						if (pending.byteLength < frameSize) break;
						const grpcPayload = pending.subarray(5, frameSize);
						pending = pending.slice(frameSize);
						if (!grpcPayload.byteLength) continue;
						let payload = grpcPayload;
						if (payload.byteLength >= 2 && payload[0] === 0x0a) {
							let shift = 0;
							let offset = 1;
							let varintValid = false;
							while (offset < payload.length) {
								const current = payload[offset++];
								if ((current & 0x80) === 0) {
									varintValid = true;
									break;
								}
								shift += 7;
								if (shift > 35) break;
							}
							if (varintValid) payload = payload.subarray(offset);
						}
						if (!payload.byteLength) continue;
						if (isDnsQuery) {
							if (isTrojan) await forwardTrojanUdp(payload, grpcBridge, trojanUdpCtx, request);
							else await forwardataudp(payload, grpcBridge, null, request);
							continue;
						}
						if (remoteConnWrapper.socket || remoteConnWrapper.connectingPromise) {
							if (!(await writeToRemote(payload))) throw new Error('Remote socket is not ready');
						} else {
							const firstPacketBytes = toUint8Array(payload);
							if (isTrojan === null) isTrojan = firstPacketBytes.byteLength >= 58 && firstPacketBytes[56] === 0x0d && firstPacketBytes[57] === 0x0a;
							if (isTrojan) {
								const parseResult = parseTrojanRequest(firstPacketBytes, yourUUID);
								if (parseResult?.hasError) throw new Error(parseResult.message || 'Invalid trojan request');
								const { port, hostname, rawClientData, isUDP } = parseResult;
								log(`[gRPC] 木马首包: ${hostname}:${port} | UDP: ${isUDP ? '是' : '否'}`);
								if (isSpeedTestSite(hostname) && proxyCtx.proxyType === null) {
									grpcBridge.send(buildLocal204Response());
									return;
								}
								if (isUDP) {
									isDnsQuery = true;
									trojanUdpCtx.targetHost = hostname;
									trojanUdpCtx.targetPort = port;
									if (trojanUdpCtx.proxyAddr) await forwardTrojanUdp(firstPacketBytes, grpcBridge, trojanUdpCtx, request);
									else if (effectiveByteLength(rawClientData) > 0) await forwardTrojanUdp(rawClientData, grpcBridge, trojanUdpCtx, request);
								} else {
									await forwardataTCP(hostname, port, rawClientData, grpcBridge, null, remoteConnWrapper, yourUUID, request, proxyCtx, true, firstPacketBytes);
								}
							} else {
								isTrojan = false;
								const parseResult = parseVlessRequest(firstPacketBytes, yourUUID);
								if (parseResult?.hasError) throw new Error(parseResult.message || 'Invalid vless request');
								const { port, hostname, version, isUDP, rawClientData } = parseResult;
								log(`[gRPC] 魏烈思首包: ${hostname}:${port} | UDP: ${isUDP ? '是' : '否'}`);
								const respHeader = new Uint8Array([version, 0]);
								if (isSpeedTestSite(hostname) && proxyCtx.proxyType === null) {
									grpcBridge.send(buildLocal204Response(respHeader));
									return;
								}
								if (isUDP) {
									if (port !== 53) throw new Error('UDP is not supported');
									isDnsQuery = true;
								}
								grpcBridge.send(respHeader);
								const rawData = rawClientData;
								if (isDnsQuery) {
									if (isTrojan) await forwardTrojanUdp(rawData, grpcBridge, trojanUdpCtx, request);
									else await forwardataudp(rawData, grpcBridge, null, request);
								}
								else await forwardataTCP(hostname, port, rawData, grpcBridge, null, remoteConnWrapper, yourUUID, request, proxyCtx);
							}
						}
					}
					flushSendQueue();
				}
				await uplinkWriteQueue.waitIdle();
			} catch (err) {
				forwardFailed = true;
				log(`[gRPC转发] 处理失败: ${err?.message || err}`);
			} finally {
				const keepTrojanUdpProxyDownlink = !forwardFailed && isDnsQuery && isTrojan && trojanUdpCtx.proxyAddr && trojanUdpCtx.proxySocket;
				if (keepTrojanUdpProxyDownlink) {
					uplinkWriteQueue.clear();
					invalidateRemoteConn();
					releaseRemoteWriter();
					try { reader.releaseLock() } catch (e) { }
				} else {
					closeConnection();
				}
			}
		},
		cancel() {
			grpcUplinkWriteQueue?.clear();
			invalidateRemoteConn();
			try { trojanUdpCtx.proxySocket?.close() } catch (e) { }
			try { reader.releaseLock() } catch (e) { }
		}
	}), { status: 200, headers: grpcHeaders });
}

///////////////////////////////////////////////////////////////////////WebSocket 传输层（早期数据解码 + 主处理）/////////////////////////////////////////////
function isValidWsEarlyData(bytes, token) {
	if (!bytes?.byteLength) return false;
	if (bytes.byteLength >= 18 && uuidBytesMatch(bytes, 1, token)) return true;
	if (bytes.byteLength < 58 || bytes[56] !== 0x0d || bytes[57] !== 0x0a) return false;

	const trojanPassword = sha224(token);
	for (let i = 0; i < 56; i++) {
		if (bytes[i] !== trojanPassword.charCodeAt(i)) return false;
	}
	return true;
}

function decodeWsEarlyData(header, token) {
	if (!header) return null;
	if (header.length > WS_EARLY_DATA_MAX_HEADER) throw new Error('early data is too large');

	let bytes;
	const Uint8ArrayBase64 = /** @type {any} */ (Uint8Array);
	if (typeof Uint8ArrayBase64.fromBase64 === 'function') {
		try {
			bytes = Uint8ArrayBase64.fromBase64(header, { alphabet: 'base64url' });
		} catch (_) { }
	}
	if (!bytes) {
		let normalized = header.replace(/-/g, '+').replace(/_/g, '/');
		const padding = normalized.length % 4;
		if (padding) normalized += '='.repeat(4 - padding);
		let binaryString;
		try {
			binaryString = atob(normalized);
		} catch (_) {
			return null;
		}
		bytes = new Uint8Array(binaryString.length);
		for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
	}

	if (bytes.byteLength > WS_EARLY_DATA_MAX_BYTES) throw new Error('early data is too large');
	return isValidWsEarlyData(bytes, token) ? bytes : null;
}

// WebSocket 入口：升级握手 + 早期数据（sec-websocket-protocol）+ 上/下行合包队列
async function handleWsRequest(request, yourUUID, url, proxyCtx = {}) {
	const wsSocketPair = new WebSocketPair();
	const [clientSock, serverSock] = Object.values(wsSocketPair);
	try { (/** @type {any} */ (serverSock)).accept({ allowHalfOpen: true }) }
	catch (_) { serverSock.accept() }
	serverSock.binaryType = 'arraybuffer';
	let remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null, downlinkDrain: Promise.resolve() };
	const invalidateRemoteConn = () => invalidateTcpGeneration(remoteConnWrapper);
	let isDnsQuery = false;
	let isTrojan = null;
	const trojanUdpCtx = { cache: new Uint8Array(0), proxyAddr: proxyCtx.trojanProxyAddr };
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
	const ssModeDisableEarlyData = !!url.searchParams.get('enc');
	let wsUplinkWriteQueue = null;
	let wsTransferChain = Promise.resolve();
	let wsTransferStopReceive = false, wsTransferFailed = false, wsTransferFinalizeQueued = false;
	let wsQueueBytes = 0, wsQueueItems = 0;
	let detectedProtocol = null, currentWriteSocket = null, remoteWriter = null;
	let ssCtx = null, ssInitTask = null;
	let wsSpeedTestMode = false, wsSpeedTestReplySocket = null;
	let wsSpeedTestRequestCache = new Uint8Array(0);
	let wsSpeedTestFirstRespHeader = null;
	const WS_SPEED_TEST_MAX_REQUESTS = 64 * 1024;

	const sendWsSpeedTestResponse = async () => {
		if (!wsSpeedTestReplySocket) return;
		const respHeader = wsSpeedTestFirstRespHeader;
		wsSpeedTestFirstRespHeader = null;
		await wsSendAndWait(wsSpeedTestReplySocket, buildWsLocal204Response(respHeader));
	};

	const findHttpHeaderEnd = (data) => {
		for (let i = 0; i <= data.byteLength - 4; i++) {
			if (data[i] === 0x0d && data[i + 1] === 0x0a && data[i + 2] === 0x0d && data[i + 3] === 0x0a) return i + 4;
		}
		return -1;
	};

	const handleWsSpeedTestData = async (data) => {
		const chunk = toUint8Array(data);
		if (!chunk.byteLength) return;
		if (wsSpeedTestRequestCache.byteLength + chunk.byteLength > WS_SPEED_TEST_MAX_REQUESTS) throw new Error('WS local speed-test request is too large');
		wsSpeedTestRequestCache = concatByteChunks(wsSpeedTestRequestCache, chunk);

		while (wsSpeedTestRequestCache.byteLength) {
			const headerEnd = findHttpHeaderEnd(wsSpeedTestRequestCache);
			if (headerEnd === -1) return;
			const headerText = vlessTextDecoder.decode(wsSpeedTestRequestCache.subarray(0, headerEnd));
			const contentLengthMatch = headerText.match(/(?:^|\r\n)content-length\s*:\s*(\d+)/i);
			const contentLength = contentLengthMatch ? Number(contentLengthMatch[1]) : 0;
			const requestLength = headerEnd + contentLength;
			if (!Number.isSafeInteger(contentLength) || requestLength > WS_SPEED_TEST_MAX_REQUESTS) throw new Error('WS local speed-test request body is too large');
			if (wsSpeedTestRequestCache.byteLength < requestLength) return;
			wsSpeedTestRequestCache = wsSpeedTestRequestCache.slice(requestLength);
			await sendWsSpeedTestResponse();
		}
	};

	const enableWsSpeedTestMode = async (replySocket, respHeader = null, firstRequestData = null) => {
		wsSpeedTestMode = true;
		wsSpeedTestReplySocket = replySocket;
		wsSpeedTestRequestCache = new Uint8Array(0);
		wsSpeedTestFirstRespHeader = respHeader;
		if (effectiveByteLength(firstRequestData) > 0) await handleWsSpeedTestData(firstRequestData);
	};

	const releaseRemoteWriter = () => {
		if (remoteWriter) {
			try { remoteWriter.releaseLock() } catch (e) { }
			remoteWriter = null;
		}
		currentWriteSocket = null;
	};

	const uplinkWriteQueue = wsUplinkWriteQueue = createUplinkWriteQueue({
		getWriter: () => {
			const socket = remoteConnWrapper.socket;
			if (!socket) return null;
			if (socket !== currentWriteSocket) {
				releaseRemoteWriter();
				currentWriteSocket = socket;
				remoteWriter = socket.writable.getWriter();
			}
			return remoteWriter;
		},
		getConnectTask: () => remoteConnWrapper.connectingPromise,
		releaseWriter: releaseRemoteWriter,
		retryConnect: async () => {
			if (typeof remoteConnWrapper.retryConnect !== 'function') throw new Error('retry unavailable');
			await remoteConnWrapper.retryConnect();
		},
		closeConnection: err => handleWsTransferError(err),
		queueName: 'WS上行'
	});

	const writeToRemote = async (chunk, allowRetry = true) => {
		return uplinkWriteQueue.write(chunk, allowRetry);
	};

	const getSsContext = async () => {
		if (ssCtx) return ssCtx;
		if (!ssInitTask) {
			ssInitTask = (async () => {
				const requestEncryptionMethod = (url.searchParams.get('enc') || '').toLowerCase();
				const preferredCryptoConfig = SS_CIPHER_CONFIGS[requestEncryptionMethod] || SS_CIPHER_CONFIGS['aes-128-gcm'];
				const inboundCandidateCrypto = [preferredCryptoConfig, ...Object.values(SS_CIPHER_CONFIGS).filter(c => c.method !== preferredCryptoConfig.method)];
				const inboundMasterKeyTaskCache = new Map();
				const getInboundMasterKeyTask = (config) => {
					if (!inboundMasterKeyTaskCache.has(config.method)) inboundMasterKeyTaskCache.set(config.method, ssDeriveMasterKey(yourUUID, config.keyLen));
					return inboundMasterKeyTaskCache.get(config.method);
				};
				const inboundState = {
					buffer: new Uint8Array(0),
					hasSalt: false,
					waitPayloadLength: null,
					decryptKey: null,
					nonceCounter: new Uint8Array(SS_NONCE_LEN),
					cryptoConfig: null,
				};
				const initInboundDecryptState = async () => {
					const lengthCipherTotalLength = 2 + SS_AEAD_TAG_LEN;
					const maxSaltLen = Math.max(...inboundCandidateCrypto.map(c => c.saltLen));
					const maxAlignScanBytes = 16;
					const maxScanOffset = Math.min(maxAlignScanBytes, Math.max(0, inboundState.buffer.byteLength - (lengthCipherTotalLength + Math.min(...inboundCandidateCrypto.map(c => c.saltLen)))));
					for (let offset = 0; offset <= maxScanOffset; offset++) {
						for (const cryptoConfig of inboundCandidateCrypto) {
							const initMinLength = offset + cryptoConfig.saltLen + lengthCipherTotalLength;
							if (inboundState.buffer.byteLength < initMinLength) continue;
							const salt = inboundState.buffer.subarray(offset, offset + cryptoConfig.saltLen);
							const lengthCipher = inboundState.buffer.subarray(offset + cryptoConfig.saltLen, initMinLength);
							const masterKey = await getInboundMasterKeyTask(cryptoConfig);
							const decryptKey = await ssDeriveSessionKey(cryptoConfig, masterKey, salt, ['decrypt']);
							const nonceCounter = new Uint8Array(SS_NONCE_LEN);
							try {
								const lengthPlain = await ssAeadDecrypt(decryptKey, nonceCounter, lengthCipher);
								if (lengthPlain.byteLength !== 2) continue;
								const payloadLength = (lengthPlain[0] << 8) | lengthPlain[1];
								if (payloadLength < 0 || payloadLength > cryptoConfig.maxChunk) continue;
								if (offset > 0) log(`[SS入站] 检测到前导噪声 ${offset}B，已自动对齐`);
								if (cryptoConfig.method !== preferredCryptoConfig.method) log(`[SS入站] URL enc=${requestEncryptionMethod || preferredCryptoConfig.method} 与实际 ${cryptoConfig.method} 不一致，已自动切换`);
								inboundState.buffer = inboundState.buffer.subarray(initMinLength);
								inboundState.decryptKey = decryptKey;
								inboundState.nonceCounter = nonceCounter;
								inboundState.waitPayloadLength = payloadLength;
								inboundState.cryptoConfig = cryptoConfig;
								inboundState.hasSalt = true;
								return true;
							} catch (_) { }
						}
					}
					const initFailGuessLength = maxSaltLen + lengthCipherTotalLength + maxAlignScanBytes;
					if (inboundState.buffer.byteLength >= initFailGuessLength) {
						throw new Error(`SS handshake decrypt failed (enc=${requestEncryptionMethod || 'auto'}, candidates=${inboundCandidateCrypto.map(c => c.method).join('/')})`);
					}
					return false;
				};
				const inboundDecryptor = {
					async input(dataChunk) {
						const chunk = toUint8Array(dataChunk);
						if (chunk.byteLength > 0) inboundState.buffer = concatByteChunks(inboundState.buffer, chunk);
						if (!inboundState.hasSalt) {
							const initSuccess = await initInboundDecryptState();
							if (!initSuccess) return [];
						}
						const plaintextChunks = [];
						while (true) {
							if (inboundState.waitPayloadLength === null) {
								const lengthCipherTotalLength = 2 + SS_AEAD_TAG_LEN;
								if (inboundState.buffer.byteLength < lengthCipherTotalLength) break;
								const lengthCipher = inboundState.buffer.subarray(0, lengthCipherTotalLength);
								inboundState.buffer = inboundState.buffer.subarray(lengthCipherTotalLength);
								const lengthPlain = await ssAeadDecrypt(inboundState.decryptKey, inboundState.nonceCounter, lengthCipher);
								if (lengthPlain.byteLength !== 2) throw new Error('SS length decrypt failed');
								const payloadLength = (lengthPlain[0] << 8) | lengthPlain[1];
								if (payloadLength < 0 || payloadLength > inboundState.cryptoConfig.maxChunk) throw new Error(`SS payload length invalid: ${payloadLength}`);
								inboundState.waitPayloadLength = payloadLength;
							}
							const payloadCipherTotalLength = inboundState.waitPayloadLength + SS_AEAD_TAG_LEN;
							if (inboundState.buffer.byteLength < payloadCipherTotalLength) break;
							const payloadCipher = inboundState.buffer.subarray(0, payloadCipherTotalLength);
							inboundState.buffer = inboundState.buffer.subarray(payloadCipherTotalLength);
							const payloadPlain = await ssAeadDecrypt(inboundState.decryptKey, inboundState.nonceCounter, payloadCipher);
							plaintextChunks.push(payloadPlain);
							inboundState.waitPayloadLength = null;
						}
						return plaintextChunks;
					},
				};
				let outboundCipher = null;
				const SS_MAX_BATCH_BYTES = 32 * 1024;
				const getOutboundCipher = async () => {
					if (outboundCipher) return outboundCipher;
					if (!inboundState.cryptoConfig) throw new Error('SS cipher is not negotiated');
					const outboundCryptoConfig = inboundState.cryptoConfig;
					const outboundMasterKey = await ssDeriveMasterKey(yourUUID, outboundCryptoConfig.keyLen);
					const outboundRandomBytes = crypto.getRandomValues(new Uint8Array(outboundCryptoConfig.saltLen));
					const outboundCipherKey = await ssDeriveSessionKey(outboundCryptoConfig, outboundMasterKey, outboundRandomBytes, ['encrypt']);
					const outboundNonceCounter = new Uint8Array(SS_NONCE_LEN);
					let randomBytesSent = false;
					outboundCipher = {
						async encryptAndSend(dataChunk, sendChunk) {
							const plaintextData = toUint8Array(dataChunk);
							if (!randomBytesSent) {
								await sendChunk(outboundRandomBytes);
								randomBytesSent = true;
							}
							if (plaintextData.byteLength === 0) return;
							let offset = 0;
							while (offset < plaintextData.byteLength) {
								const end = Math.min(offset + outboundCryptoConfig.maxChunk, plaintextData.byteLength);
								const payloadPlain = plaintextData.subarray(offset, end);
								const lengthPlain = new Uint8Array(2);
								lengthPlain[0] = (payloadPlain.byteLength >>> 8) & 0xff;
								lengthPlain[1] = payloadPlain.byteLength & 0xff;
								const lengthCipher = await ssAeadEncrypt(outboundCipherKey, outboundNonceCounter, lengthPlain);
								const payloadCipher = await ssAeadEncrypt(outboundCipherKey, outboundNonceCounter, payloadPlain);
								const frame = new Uint8Array(lengthCipher.byteLength + payloadCipher.byteLength);
								frame.set(lengthCipher, 0);
								frame.set(payloadCipher, lengthCipher.byteLength);
								await sendChunk(frame);
								offset = end;
							}
						},
					};
					return outboundCipher;
				};
				let ssSendQueue = Promise.resolve();
				const ssEnqueueSend = (chunk) => {
					ssSendQueue = ssSendQueue.then(async () => {
						if (serverSock.readyState !== WebSocket.OPEN) return;
						const outboundCipherInitialized = await getOutboundCipher();
						await outboundCipherInitialized.encryptAndSend(chunk, async (encryptedChunk) => {
							if (encryptedChunk.byteLength > 0 && serverSock.readyState === WebSocket.OPEN) {
								await wsSendAndWait(serverSock, encryptedChunk.buffer);
							}
						});
					}).catch((error) => {
						log(`[SS发送] 加密失败: ${error?.message || error}`);
						closeSocketQuietly(serverSock);
					});
					return ssSendQueue;
				};
				const replySocket = {
					get readyState() {
						return serverSock.readyState;
					},
					send(data) {
						const chunk = toUint8Array(data);
						if (chunk.byteLength <= SS_MAX_BATCH_BYTES) {
							return ssEnqueueSend(chunk);
						}
						for (let i = 0; i < chunk.byteLength; i += SS_MAX_BATCH_BYTES) {
							ssEnqueueSend(chunk.subarray(i, Math.min(i + SS_MAX_BATCH_BYTES, chunk.byteLength)));
						}
						return ssSendQueue;
					},
					close() {
						closeSocketQuietly(serverSock);
					}
				};
				ssCtx = {
					inboundDecryptor,
					replySocket,
					firstPacketEstablished: false,
					targetHost: '',
					targetPort: 0,
				};
				return ssCtx;
			})().finally(() => { ssInitTask = null });
		}
		return ssInitTask;
	};

	const handleSsData = async (chunk) => {
		const ctx = await getSsContext();
		let plainChunkList = null;
		try {
			plainChunkList = await ctx.inboundDecryptor.input(chunk);
		} catch (err) {
			const msg = err?.message || `${err}`;
			if (msg.includes('Decryption failed') || msg.includes('SS handshake decrypt failed') || msg.includes('SS length decrypt failed')) {
				log(`[SS入站] 解密失败，连接关闭: ${msg}`);
				closeSocketQuietly(serverSock);
				return;
			}
			throw err;
		}
		for (const plainChunk of plainChunkList) {
			if (wsSpeedTestMode) {
				await handleWsSpeedTestData(plainChunk);
				continue;
			}
			let written = false;
			try {
				written = await writeToRemote(plainChunk, false);
			} catch (err) {
				if ((/** @type {any} */ (err))?.isQueueOverflow) throw err;
				written = false;
			}
			if (written) continue;
			if (ctx.firstPacketEstablished && ctx.targetHost && ctx.targetPort > 0) {
				await forwardataTCP(ctx.targetHost, ctx.targetPort, plainChunk, ctx.replySocket, null, remoteConnWrapper, yourUUID, request, proxyCtx);
				continue;
			}
			const plainData = toUint8Array(plainChunk);
			if (plainData.byteLength < 3) throw new Error('invalid ss data');
			const addressType = plainData[0];
			let cursor = 1;
			let hostname = '';
			if (addressType === 1) {
				if (plainData.byteLength < cursor + 4 + 2) throw new Error('invalid ss ipv4 length');
				hostname = `${plainData[cursor]}.${plainData[cursor + 1]}.${plainData[cursor + 2]}.${plainData[cursor + 3]}`;
				cursor += 4;
			} else if (addressType === 3) {
				if (plainData.byteLength < cursor + 1) throw new Error('invalid ss domain length');
				const domainLength = plainData[cursor];
				cursor += 1;
				if (plainData.byteLength < cursor + domainLength + 2) throw new Error('invalid ss domain data');
				hostname = ssTextDecoder.decode(plainData.subarray(cursor, cursor + domainLength));
				cursor += domainLength;
			} else if (addressType === 4) {
				if (plainData.byteLength < cursor + 16 + 2) throw new Error('invalid ss ipv6 length');
				const ipv6 = [];
				const ipv6View = new DataView(plainData.buffer, plainData.byteOffset + cursor, 16);
				for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16));
				hostname = ipv6.join(':');
				cursor += 16;
			} else {
				throw new Error(`invalid ss addressType: ${addressType}`);
			}
			if (!hostname) throw new Error(`invalid ss address: ${addressType}`);
			const port = (plainData[cursor] << 8) | plainData[cursor + 1];
			cursor += 2;
			const rawClientData = plainData.subarray(cursor);
			if (isSpeedTestSite(hostname) && proxyCtx.proxyType === null) {
				await enableWsSpeedTestMode(ctx.replySocket, null, rawClientData);
				return;
			}
			ctx.firstPacketEstablished = true;
			ctx.targetHost = hostname;
			ctx.targetPort = port;
			await forwardataTCP(hostname, port, rawClientData, ctx.replySocket, null, remoteConnWrapper, yourUUID, request, proxyCtx);
		}
	};

	const handleWsInboundData = async (chunk) => {
		let currentChunkBytes = null;
		if (isDnsQuery) {
			if (isTrojan) return await forwardTrojanUdp(chunk, serverSock, trojanUdpCtx, request);
			return await forwardataudp(chunk, serverSock, null, request);
		}
		if (detectedProtocol === 'ss') {
			await handleSsData(chunk);
			return;
		}
		if (wsSpeedTestMode) {
			await handleWsSpeedTestData(chunk);
			return;
		}
		if (await writeToRemote(chunk)) return;

		if (detectedProtocol === null) {
			if (url.searchParams.get('enc')) detectedProtocol = 'ss';
			else {
				currentChunkBytes = currentChunkBytes || toUint8Array(chunk);
				const bytes = currentChunkBytes;
				detectedProtocol = bytes.byteLength >= 58 && bytes[56] === 0x0d && bytes[57] === 0x0a ? 'trojan' : 'vless';
			}
			isTrojan = detectedProtocol === 'trojan';
			log(`[WS转发] 协议类型: ${detectedProtocol} | 来自: ${url.host} | UA: ${request.headers.get('user-agent') || '未知'}`);
		}

		if (detectedProtocol === 'ss') {
			await handleSsData(chunk);
			return;
		}
		if (await writeToRemote(chunk)) return;
		if (detectedProtocol === 'trojan') {
			const parseResult = parseTrojanRequest(chunk, yourUUID);
			if (parseResult?.hasError) throw new Error(parseResult.message || 'Invalid trojan request');
			const { port, hostname, rawClientData, isUDP } = parseResult;
			if (isSpeedTestSite(hostname) && proxyCtx.proxyType === null) {
				await enableWsSpeedTestMode(serverSock, null, rawClientData);
				return;
			}
			if (isUDP) {
				isDnsQuery = true;
				trojanUdpCtx.targetHost = hostname;
				trojanUdpCtx.targetPort = port;
				if (trojanUdpCtx.proxyAddr) return forwardTrojanUdp(currentChunkBytes || toUint8Array(chunk), serverSock, trojanUdpCtx, request);
				if (effectiveByteLength(rawClientData) > 0) return forwardTrojanUdp(rawClientData, serverSock, trojanUdpCtx, request);
				return;
			}
			await forwardataTCP(hostname, port, rawClientData, serverSock, null, remoteConnWrapper, yourUUID, request, proxyCtx, true, currentChunkBytes || toUint8Array(chunk));
		} else {
			isTrojan = false;
			currentChunkBytes = currentChunkBytes || toUint8Array(chunk);
			const bytes = currentChunkBytes;
			const parseResult = parseVlessRequest(bytes, yourUUID);
			if (parseResult?.hasError) throw new Error(parseResult.message || 'Invalid vless request');
			const { port, hostname, version, isUDP, rawClientData } = parseResult;
			const respHeader = new Uint8Array([version, 0]);
			if (isSpeedTestSite(hostname) && proxyCtx.proxyType === null) {
				await enableWsSpeedTestMode(serverSock, respHeader, rawClientData);
				return;
			}
			if (isUDP) {
				if (port === 53) isDnsQuery = true;
				else throw new Error('UDP is not supported');
			}
			const rawData = rawClientData;
			if (isDnsQuery) {
				if (isTrojan) return forwardTrojanUdp(rawData, serverSock, trojanUdpCtx, request);
				return forwardataudp(rawData, serverSock, respHeader, request);
			}
			await forwardataTCP(hostname, port, rawData, serverSock, respHeader, remoteConnWrapper, yourUUID, request, proxyCtx);
		}
	};

	const handleWsTransferError = (err) => {
		if (wsTransferFailed) return;
		wsTransferFailed = true;
		wsTransferStopReceive = true;
		wsQueueBytes = 0;
		wsQueueItems = 0;
		const msg = err?.message || `${err}`;
		if (msg.includes('Network connection lost') || msg.includes('ReadableStream is closed')) {
			log(`[WS转发] 连接结束: ${msg}`);
		} else {
			log(`[WS转发] 处理失败: ${msg}`);
		}
		uplinkWriteQueue.clear();
		releaseRemoteWriter();
		invalidateRemoteConn();
		try { trojanUdpCtx.proxySocket?.close() } catch (e) { }
		closeSocketQuietly(serverSock);
	};

	const appendWsTransferTask = (task) => {
		wsTransferChain = wsTransferChain.then(task).catch(handleWsTransferError);
		return wsTransferChain;
	};

	const enqueueWsTransfer = (data) => {
		if (wsTransferStopReceive || wsTransferFailed) return;
		const chunkSize = Math.max(0, effectiveByteLength(data));
		const nextBytes = wsQueueBytes + chunkSize;
		const nextItems = wsQueueItems + 1;
		if (nextBytes > UPLINK_QUEUE_MAX_BYTES || nextItems > UPLINK_QUEUE_MAX_ITEMS) {
			handleWsTransferError(new Error(`[WS显式传输] 队列溢出: ${nextBytes}B/${nextItems}`));
			return;
		}
		wsQueueBytes = nextBytes;
		wsQueueItems = nextItems;
		appendWsTransferTask(async () => {
			wsQueueBytes = Math.max(0, wsQueueBytes - chunkSize);
			wsQueueItems = Math.max(0, wsQueueItems - 1);
			if (wsTransferFailed) return;
			await handleWsInboundData(data);
		});
	};

	const finalizeWsTransfer = () => {
		if (wsTransferFinalizeQueued) return;
		wsTransferFinalizeQueued = true;
		wsTransferStopReceive = true;
		appendWsTransferTask(async () => {
			if (wsTransferFailed) return;
			await uplinkWriteQueue.waitIdle();
			releaseRemoteWriter();
			invalidateRemoteConn();
			try { trojanUdpCtx.proxySocket?.close() } catch (e) { }
		});
	};

	serverSock.addEventListener('message', (event) => {
		enqueueWsTransfer(event.data);
	});
	serverSock.addEventListener('close', () => {
		closeSocketQuietly(serverSock);
		finalizeWsTransfer();
	});
	serverSock.addEventListener('error', (err) => {
		handleWsTransferError(err);
	});

	// SS 模式下禁用 sec-websocket-protocol early-data，避免把子协议值（如 "binary"）误当作 base64 数据注入首包导致 AEAD 解密失败。
	if (!ssModeDisableEarlyData && earlyDataHeader) {
		try {
			const bytes = decodeWsEarlyData(earlyDataHeader, yourUUID);
			if (bytes?.byteLength) enqueueWsTransfer(bytes.buffer);
		} catch (error) {
			handleWsTransferError(error);
		}
	}

	return new Response(null, { status: 101, webSocket: clientSock, headers: { 'Sec-WebSocket-Extensions': '' } });
}

const trojanTextDecoder = new TextDecoder();

///////////////////////////////////////////////////////协议解析（VLESS / Trojan / Shadowsocks）与 SS 加密///////////////////////////////////////////////
function parseTrojanProxyAddr(address) {
	const raw = String(address || '').trim();
	if (!raw || raw.includes('/') || raw.includes('@') || raw.includes('://')) throw new Error('木马反代仅支持 host:port');
	let hostname = '', portText = '';
	if (raw.startsWith('[')) {
		const match = raw.match(/^(\[[^\]]+\]):(\d+)$/);
		if (!match) throw new Error('无效的 IPv6 木马反代地址');
		hostname = match[1];
		portText = match[2];
	} else {
		const parts = raw.split(':');
		if (parts.length !== 2) throw new Error('木马反代仅支持 host:port');
		hostname = parts[0];
		portText = parts[1];
	}
	const port = Number(portText);
	if (!hostname || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error('无效的木马反代端口');
	return { hostname, port };
}

async function connectTrojanProxy(firstPacketData, tcpConnect, trojanProxyTarget) {
	if (!trojanProxyTarget) throw new Error('trojan fallback is not configured');
	const socket = tcpConnect({ hostname: stripIPv6Brackets(trojanProxyTarget.hostname), port: trojanProxyTarget.port });
	let writer = null;
	try {
		if (socket.opened) await socket.opened;
		if (effectiveByteLength(firstPacketData) > 0) {
			writer = socket.writable.getWriter();
			await writer.write(toUint8Array(firstPacketData));
		}
		return socket;
	} catch (error) {
		try { socket?.close?.() } catch (e) { }
		throw error;
	} finally {
		try { writer?.releaseLock() } catch (e) { }
	}
}

function extractTrojanProxyHandshake(firstPacketData, rawData) {
	const firstPacket = toUint8Array(firstPacketData);
	const payload = toUint8Array(rawData);
	if (!payload.byteLength) return firstPacket;
	const handshakeLen = firstPacket.byteLength - payload.byteLength;
	if (handshakeLen <= 0) return firstPacket;
	for (let i = 0; i < payload.byteLength; i++) {
		if (firstPacket[handshakeLen + i] !== payload[i]) return firstPacket;
	}
	return firstPacket.subarray(0, handshakeLen);
}

async function forwardTrojanUdpProxy(chunk, webSocket, ctx, request) {
	const data = toUint8Array(chunk);
	if (!ctx.proxySocket) {
		const tcpConnect = createRequestTcpConnector(request);
		const socket = await connectTrojanProxy(data, tcpConnect, ctx.proxyAddr);
		ctx.proxySocket = socket;
		socket.closed.catch(() => { }).finally(() => closeSocketQuietly(webSocket));
		connectStreams(socket, webSocket, null, null);
		return;
	}
	if (!data.byteLength) return;
	const writer = ctx.proxySocket.writable.getWriter();
	try { await writer.write(data) }
	finally { try { writer.releaseLock() } catch (e) { } }
}

function parseTrojanRequest(buffer, passwordPlainText) {
	const data = toUint8Array(buffer);
	const sha224Password = sha224(passwordPlainText);
	if (data.byteLength < 58) return { hasError: true, message: "invalid data" };
	let crLfIndex = 56;
	if (data[crLfIndex] !== 0x0d || data[crLfIndex + 1] !== 0x0a) return { hasError: true, message: "invalid header format" };
	for (let i = 0; i < crLfIndex; i++) {
		if (data[i] !== sha224Password.charCodeAt(i)) return { hasError: true, message: "invalid password" };
	}

	const socks5Index = crLfIndex + 2;
	if (data.byteLength < socks5Index + 6) return { hasError: true, message: "invalid S5 request data" };

	const cmd = data[socks5Index];
	if (cmd !== 1 && cmd !== 3) return { hasError: true, message: "unsupported command, only TCP/UDP is allowed" };
	const isUDP = cmd === 3;

	const atype = data[socks5Index + 1];
	let addressLength = 0;
	let addressIndex = socks5Index + 2;
	let address = "";
	switch (atype) {
		case 1: // IPv4
			addressLength = 4;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: "invalid S5 request data" };
			address = `${data[addressIndex]}.${data[addressIndex + 1]}.${data[addressIndex + 2]}.${data[addressIndex + 3]}`;
			break;
		case 3: // Domain
			if (data.byteLength < addressIndex + 1) return { hasError: true, message: "invalid S5 request data" };
			addressLength = data[addressIndex];
			addressIndex += 1;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: "invalid S5 request data" };
			address = trojanTextDecoder.decode(data.subarray(addressIndex, addressIndex + addressLength));
			break;
		case 4: // IPv6
			addressLength = 16;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: "invalid S5 request data" };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const partIndex = addressIndex + i * 2;
				ipv6.push(((data[partIndex] << 8) | data[partIndex + 1]).toString(16));
			}
			address = ipv6.join(":");
			break;
		default:
			return { hasError: true, message: `invalid addressType is ${atype}` };
	}

	if (!address) {
		return { hasError: true, message: `address is empty, addressType is ${atype}` };
	}

	const portIndex = addressIndex + addressLength;
	if (data.byteLength < portIndex + 4) return { hasError: true, message: "invalid S5 request data" };
	const portRemote = (data[portIndex] << 8) | data[portIndex + 1];

	return {
		hasError: false,
		addressType: atype,
		port: portRemote,
		hostname: address,
		isUDP,
		rawClientData: data.subarray(portIndex + 4)
	};
}

const uuidBytesCache = new Map();
const vlessTextDecoder = new TextDecoder();

function readHexNibble(code) {
	if (code >= 48 && code <= 57) return code - 48;
	code |= 32;
	if (code >= 97 && code <= 102) return code - 87;
	return -1;
}

function getUuidBytes(uuid) {
	const key = String(uuid || '');
	let cached = uuidBytesCache.get(key);
	if (cached) return cached;

	const clean = key.replace(/-/g, '');
	if (clean.length !== 32) return null;

	const bytes = new Uint8Array(16);
	for (let i = 0; i < 16; i++) {
		const high = readHexNibble(clean.charCodeAt(i * 2));
		const low = readHexNibble(clean.charCodeAt(i * 2 + 1));
		if (high < 0 || low < 0) return null;
		bytes[i] = (high << 4) | low;
	}

	if (uuidBytesCache.size >= 32) uuidBytesCache.clear();
	uuidBytesCache.set(key, bytes);
	return bytes;
}

function uuidBytesMatch(data, offset, uuid) {
	const expected = getUuidBytes(uuid);
	if (!expected || data.byteLength < offset + 16) return false;
	for (let i = 0; i < 16; i++) {
		if (data[offset + i] !== expected[i]) return false;
	}
	return true;
}

function parseVlessRequest(chunk, token) {
	const data = toUint8Array(chunk);
	const length = data.byteLength;
	if (length < 24) return { hasError: true, message: 'Invalid data' };
	const version = data[0];
	if (!uuidBytesMatch(data, 1, token)) return { hasError: true, message: 'Invalid uuid' };

	const optLen = data[17];
	const cmdIndex = 18 + optLen;
	if (length < cmdIndex + 4) return { hasError: true, message: 'Invalid data' };

	const cmd = data[cmdIndex];
	let isUDP = false;
	if (cmd === 1) { } else if (cmd === 2) { isUDP = true } else { return { hasError: true, message: 'Invalid command' } }

	const portIdx = cmdIndex + 1;
	const port = (data[portIdx] << 8) | data[portIdx + 1];
	let addrValIdx = portIdx + 3, addrLen = 0, hostname = '';
	const addressType = data[portIdx + 2];
	switch (addressType) {
		case 1:
			addrLen = 4;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid IPv4 address length' };
			hostname = `${data[addrValIdx]}.${data[addrValIdx + 1]}.${data[addrValIdx + 2]}.${data[addrValIdx + 3]}`;
			break;
		case 2:
			if (length < addrValIdx + 1) return { hasError: true, message: 'Invalid domain length' };
			addrLen = data[addrValIdx];
			addrValIdx += 1;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid domain data' };
			hostname = vlessTextDecoder.decode(data.subarray(addrValIdx, addrValIdx + addrLen));
			break;
		case 3:
			addrLen = 16;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid IPv6 address length' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = addrValIdx + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			break;
		default:
			return { hasError: true, message: `Invalid address type: ${addressType}` };
	}
	if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };
	const rawIndex = addrValIdx + addrLen;
	return { hasError: false, addressType, port, hostname, isUDP, rawClientData: data.subarray(rawIndex), version };
}

const SS_CIPHER_CONFIGS = {
	'aes-128-gcm': { method: 'aes-128-gcm', keyLen: 16, saltLen: 16, maxChunk: 0x3fff, aesLength: 128 },
	'aes-256-gcm': { method: 'aes-256-gcm', keyLen: 32, saltLen: 32, maxChunk: 0x3fff, aesLength: 256 },
};

const SS_AEAD_TAG_LEN = 16, SS_NONCE_LEN = 12;
const SS_SUBKEY_INFO = new TextEncoder().encode('ss-subkey');
const ssTextEncoder = new TextEncoder(), ssTextDecoder = new TextDecoder(), ssMasterKeyCache = new Map();

function toUint8Array(data) {
	if (data instanceof Uint8Array) return data;
	if (data instanceof ArrayBuffer) return new Uint8Array(data);
	if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	return new Uint8Array(data || 0);
}

function concatByteChunks(...chunkList) {
	if (!chunkList || chunkList.length === 0) return new Uint8Array(0);
	const chunks = chunkList.map(toUint8Array);
	const total = chunks.reduce((sum, c) => sum + c.byteLength, 0);
	const result = new Uint8Array(total);
	let offset = 0;
	for (const c of chunks) { result.set(c, offset); offset += c.byteLength }
	return result;
}

async function forwardTrojanUdp(chunk, webSocket, ctx, request) {
	const currentChunk = toUint8Array(chunk);
	if (ctx?.proxyAddr) return forwardTrojanUdpProxy(currentChunk, webSocket, ctx, request);
	const cachedChunk = ctx?.cache instanceof Uint8Array ? ctx.cache : new Uint8Array(0);
	const input = cachedChunk.byteLength ? concatByteChunks(cachedChunk, currentChunk) : currentChunk;
	let cursor = 0;

	while (cursor < input.byteLength) {
		const packetStart = cursor;
		const atype = input[cursor];
		let addrCursor = cursor + 1;
		let addrLen = 0;
		if (atype === 1) addrLen = 4;
		else if (atype === 4) addrLen = 16;
		else if (atype === 3) {
			if (input.byteLength < addrCursor + 1) break;
			addrLen = 1 + input[addrCursor];
		} else throw new Error(`invalid trojan udp addressType: ${atype}`);

		const portCursor = addrCursor + addrLen;
		if (input.byteLength < portCursor + 6) break;

		const port = (input[portCursor] << 8) | input[portCursor + 1];
		const payloadLength = (input[portCursor + 2] << 8) | input[portCursor + 3];
		if (input[portCursor + 4] !== 0x0d || input[portCursor + 5] !== 0x0a) throw new Error('invalid trojan udp delimiter');

		const payloadStart = portCursor + 6;
		const payloadEnd = payloadStart + payloadLength;
		if (input.byteLength < payloadEnd) break;

		const addrPortHeader = input.slice(packetStart, portCursor + 2);
		const payload = input.slice(payloadStart, payloadEnd);
		cursor = payloadEnd;

		if (port !== 53) throw new Error('UDP is not supported');
		if (!payload.byteLength) continue;

		let tcpDnsQuery = payload;
		if (payload.byteLength < 2 || ((payload[0] << 8) | payload[1]) !== payload.byteLength - 2) {
			tcpDnsQuery = new Uint8Array(payload.byteLength + 2);
			tcpDnsQuery[0] = (payload.byteLength >>> 8) & 0xff;
			tcpDnsQuery[1] = payload.byteLength & 0xff;
			tcpDnsQuery.set(payload, 2);
		}

		const dnsResponseCtx = { cache: new Uint8Array(0) };
		await forwardataudp(tcpDnsQuery, webSocket, null, request, (dnsRespChunk) => {
			const currentResponseChunk = toUint8Array(dnsRespChunk);
			const responseInput = dnsResponseCtx.cache.byteLength ? concatByteChunks(dnsResponseCtx.cache, currentResponseChunk) : currentResponseChunk;
			const responseFrames = [];
			let responseCursor = 0;
			while (responseCursor + 2 <= responseInput.byteLength) {
				const dnsLen = (responseInput[responseCursor] << 8) | responseInput[responseCursor + 1];
				const dnsStart = responseCursor + 2;
				const dnsEnd = dnsStart + dnsLen;
				if (dnsEnd > responseInput.byteLength) break;
				const dnsPayload = responseInput.slice(dnsStart, dnsEnd);
				const frame = new Uint8Array(addrPortHeader.byteLength + 4 + dnsPayload.byteLength);
				frame.set(addrPortHeader, 0);
				frame[addrPortHeader.byteLength] = (dnsPayload.byteLength >>> 8) & 0xff;
				frame[addrPortHeader.byteLength + 1] = dnsPayload.byteLength & 0xff;
				frame[addrPortHeader.byteLength + 2] = 0x0d;
				frame[addrPortHeader.byteLength + 3] = 0x0a;
				frame.set(dnsPayload, addrPortHeader.byteLength + 4);
				responseFrames.push(frame);
				responseCursor = dnsEnd;
			}
			dnsResponseCtx.cache = responseInput.slice(responseCursor);
			return responseFrames.length ? responseFrames : new Uint8Array(0);
		});
	}

	if (ctx) ctx.cache = input.slice(cursor);
}

function ssIncrementNonce(counter) {
	for (let i = 0; i < counter.length; i++) { counter[i] = (counter[i] + 1) & 0xff; if (counter[i] !== 0) return }
}

async function ssDeriveMasterKey(passwordText, keyLen) {
	const cacheKey = `${keyLen}:${passwordText}`;
	if (ssMasterKeyCache.has(cacheKey)) return ssMasterKeyCache.get(cacheKey);
	const deriveTask = (async () => {
		const pwBytes = ssTextEncoder.encode(passwordText || '');
		let prev = new Uint8Array(0), result = new Uint8Array(0);
		while (result.byteLength < keyLen) {
			const input = new Uint8Array(prev.byteLength + pwBytes.byteLength);
			input.set(prev, 0); input.set(pwBytes, prev.byteLength);
			prev = new Uint8Array(await crypto.subtle.digest('MD5', input));
			result = concatByteChunks(result, prev);
		}
		return result.slice(0, keyLen);
	})();
	ssMasterKeyCache.set(cacheKey, deriveTask);
	try { return await deriveTask }
	catch (error) { ssMasterKeyCache.delete(cacheKey); throw error }
}

async function ssDeriveSessionKey(config, masterKey, salt, usages) {
	const hmacOpts = { name: 'HMAC', hash: 'SHA-1' };
	const saltHmacKey = await crypto.subtle.importKey('raw', salt, hmacOpts, false, ['sign']);
	const prk = new Uint8Array(await crypto.subtle.sign('HMAC', saltHmacKey, masterKey));
	const prkHmacKey = await crypto.subtle.importKey('raw', prk, hmacOpts, false, ['sign']);
	const subKey = new Uint8Array(config.keyLen);
	let prev = new Uint8Array(0), written = 0, counter = 1;
	while (written < config.keyLen) {
		const input = concatByteChunks(prev, SS_SUBKEY_INFO, new Uint8Array([counter]));
		prev = new Uint8Array(await crypto.subtle.sign('HMAC', prkHmacKey, input));
		const copyLen = Math.min(prev.byteLength, config.keyLen - written);
		subKey.set(prev.subarray(0, copyLen), written);
		written += copyLen; counter += 1;
	}
	return crypto.subtle.importKey('raw', subKey, { name: 'AES-GCM', length: config.aesLength }, false, usages);
}

async function ssAeadEncrypt(cryptoKey, nonceCounter, plaintext) {
	const iv = nonceCounter.slice();
	const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, cryptoKey, plaintext);
	ssIncrementNonce(nonceCounter);
	return new Uint8Array(ct);
}

async function ssAeadDecrypt(cryptoKey, nonceCounter, ciphertext) {
	const iv = nonceCounter.slice();
	const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, cryptoKey, ciphertext);
	ssIncrementNonce(nonceCounter);
	return new Uint8Array(pt);
}

///////////////////////////////////////////////////////TCP/UDP 转发核心（连接世代 / 链式调度 / Grain 合包队列）///////////////////////////////////////////////
// 所有 TCP 出站流量的唯一收口：直连 / ProxyIP 反代 / SOCKS5·HTTP·HTTPS·TURN·SSTP 链式代理的调度都在这里分叉。
async function forwardataTCP(host, portNum, rawData, ws, respHeader, remoteConnWrapper, yourUUID, request = null, proxyCtx = {}, allowTrojanProxy = false, trojanProxyFirstPacket = null, connectOnly = false) {
	const ctxProxyIP = proxyCtx.proxyIP || '';
	const ctxProxyType = proxyCtx.proxyType !== undefined ? proxyCtx.proxyType : null;
	const ctxProxyGlobal = proxyCtx.proxyGlobal !== undefined ? proxyCtx.proxyGlobal : false;
	const ctxProxyParams = proxyCtx.proxyParams || {};
	const ctxProxyFallback = proxyCtx.proxyFallback !== undefined ? proxyCtx.proxyFallback : true;
	let proxyListIndex = 0;
	log(`[TCP转发] 目标: ${host}:${portNum} | 反代IP: ${ctxProxyIP} | 反代兜底: ${ctxProxyFallback ? '是' : '否'} | 反代类型: ${ctxProxyType || 'proxyip'} | 全局: ${ctxProxyGlobal ? '是' : '否'}`);
	const connectTimeoutMs = 1000;
	let firstPacketSentViaProxy = false;
	const tcpConnect = createRequestTcpConnector(request);
	const useTrojanProxy = allowTrojanProxy && (proxyCtx.trojanProxyAddr || null);
	const trojanProxyTarget = useTrojanProxy ? proxyCtx.trojanProxyAddr : null;
	const trojanProxyHandshake = useTrojanProxy ? extractTrojanProxyHandshake(trojanProxyFirstPacket, rawData) : null;
	let pendingRespHeader = respHeader;
	const takeRespHeader = () => {
		const header = pendingRespHeader;
		pendingRespHeader = null;
		return header;
	};
	if (!Number.isInteger(remoteConnWrapper.generation)) remoteConnWrapper.generation = 0;

	const installCurrentConnection = async (socket, generation, downlinkDrain, retryFunc = null) => {
		try { await downlinkDrain } catch (e) {
			if (remoteConnWrapper.downlinkDrain === downlinkDrain) remoteConnWrapper.downlinkDrain = Promise.resolve();
			try { socket?.close?.() } catch (_) { }
			if (remoteConnWrapper.generation === generation) closeSocketQuietly(ws);
			throw e;
		}
		if (remoteConnWrapper.downlinkDrain === downlinkDrain) remoteConnWrapper.downlinkDrain = Promise.resolve();
		const isConnStillValid = () => remoteConnWrapper.generation === generation && remoteConnWrapper.socket === socket;
		if (remoteConnWrapper.generation !== generation || ws.readyState !== WebSocket.OPEN) {
			try { socket?.close?.() } catch (e) { }
			if (remoteConnWrapper.generation === generation) remoteConnWrapper.socket = null;
			throw new Error('connection superseded or client closed');
		}
		remoteConnWrapper.socket = socket;
		if (connectOnly) return socket;
		connectStreams(socket, ws, takeRespHeader, retryFunc, isConnStillValid, remoteConnWrapper).catch(err => {
			if (!isConnStillValid()) return;
			log(`[TCP下行] 处理失败: ${err?.message || err}`);
			try { socket?.close?.() } catch (e) { }
			closeSocketQuietly(ws);
		});
		return true;
	};

	async function waitForConnectionOpen(remoteSock, timeoutMs = connectTimeoutMs) {
		await Promise.race([
			remoteSock.opened,
			new Promise((_, reject) => setTimeout(() => reject(new Error('连接超时')), timeoutMs))
		]);
	}

	async function openTcpConnection(address, port) {
		const remoteSock = tcpConnect({ hostname: address, port });
		try {
			await waitForConnectionOpen(remoteSock);
			return remoteSock;
		} catch (err) {
			try { remoteSock?.close?.() } catch (e) { }
			throw err;
		}
	}

	async function writeFirstPacket(remoteSock, data) {
		if (effectiveByteLength(data) <= 0) return;
		const writer = remoteSock.writable.getWriter();
		try { await writer.write(toUint8Array(data)) }
		finally { try { writer.releaseLock() } catch (e) { } }
	}

	async function openCandidatesConcurrent(candidateList) {
		if (candidateList.length === 1) {
			const candidate = candidateList[0];
			return { socket: await openTcpConnection(candidate.hostname, candidate.port), candidate: candidate };
		}
		const attempts = candidateList.map(candidate => openTcpConnection(candidate.hostname, candidate.port).then(socket => ({ socket, candidate: candidate })));
		let winner = null;
		try {
			winner = await Promise.any(attempts);
			return winner;
		} finally {
			if (winner) {
				for (const attempt of attempts) {
					attempt.then(({ socket }) => {
						if (socket !== winner.socket) {
							try { socket?.close?.() } catch (e) { }
						}
					}).catch(() => { });
				}
			}
		}
	}

	async function buildPreloadRaceCandidates(address, port) {
		if (!preloadRaceDial || isIPHostname(address)) return null;
		log(`[TCP直连] 预加载竞速拨号开启，开始并发查询 ${address} 的 A/AAAA 记录`);
		const [aRecords, aaaaRecords] = await Promise.all([
			dohQuery(address, 'A'),
			dohQuery(address, 'AAAA')
		]);
		const ipv4List = [...new Set(aRecords.flatMap(r => {
			const data = r.data;
			return r.type === 1 && typeof data === 'string' && isIPv4(data) ? [data] : [];
		}))];
		const ipv6List = [...new Set(aaaaRecords.flatMap(r => {
			const data = r.data;
			return r.type === 28 && typeof data === 'string' && isIPHostname(data) ? [data] : [];
		}))];
		const dialLimit = Math.max(1, tcpConcurrentDial | 0);
		const ipList = ipv4List.length >= dialLimit
			? ipv4List.slice(0, dialLimit)
			: ipv4List.concat(ipv6List.slice(0, dialLimit - ipv4List.length));
		const recordTypeUsed = ipv4List.length > 0
			? (ipList.length > ipv4List.length ? 'A+AAAA' : 'A')
			: 'AAAA';
		if (ipList.length === 0) {
			log(`[TCP直连] ${address} 的 A/AAAA 未获得可用解析结果，预加载竞速不可用，回退到原始 hostname 直连。`);
			return null;
		}
		const selectedIPList = ipList;
		log(`[TCP直连] ${address} A记录:${ipv4List.length} AAAA记录:${ipv6List.length}，使用${recordTypeUsed}记录，竞速拨号 ${selectedIPList.length}/${dialLimit}: ${selectedIPList.join(', ')}`);
		return selectedIPList.map((hostname, attempt) => ({ hostname, port, attempt, resolvedFrom: address }));
	}

	async function connectDirect(address, port, data = null, enablePreload = false) {
		const preloadCandidateList = enablePreload ? await buildPreloadRaceCandidates(address, port) : null;
		const candidateList = preloadCandidateList || Array.from({ length: tcpConcurrentDial }, (_, attempt) => ({ hostname: address, port, attempt }));
		log(preloadCandidateList
			? `[TCP直连] 并发尝试 ${candidateList.length} 路: ${candidateList.map(candidate => `${candidate.hostname}:${candidate.port}`).join(', ')}`
			: `[TCP直连] 并发尝试 ${candidateList.length} 路: ${address}:${port}`);
		let socket = null;
		try {
			const connectResult = await openCandidatesConcurrent(candidateList);
			socket = connectResult.socket;
			if (preloadCandidateList) {
				const winner = connectResult.candidate;
				log(`[TCP直连] 预加载竞速结果: ${winner.hostname}:${winner.port} 胜出，源域名: ${winner.resolvedFrom || address}`);
			}
			await writeFirstPacket(socket, data);
			return socket;
		} catch (err) {
			try { socket?.close?.() } catch (e) { }
			if (preloadCandidateList) log(`[TCP直连] 预加载竞速失败: ${err.message || err}`);
			throw err;
		}
	}

	async function connectProxyIP(address, port, data = null, allProxyList = null, allowProxyFallback = true) {
		if (allProxyList && allProxyList.length > 0) {
			const actualConcurrency = Math.max(1, Math.floor(Number(proxyConcurrentDial) || 1));
			for (let i = 0; i < allProxyList.length; i += actualConcurrency) {
				const candidateList = [];
				for (let j = 0; j < actualConcurrency && i + j < allProxyList.length; j++) {
					const index = (proxyListIndex + i + j) % allProxyList.length;
					const [proxyAddr, proxyPort] = allProxyList[index];
					candidateList.push({ hostname: proxyAddr, port: proxyPort, index: index });
				}
				let socket = null, candidate = null;
				try {
					log(`[反代连接] 并发尝试 ${candidateList.length} 路: ${candidateList.map(candidate => `${candidate.hostname}:${candidate.port}`).join(', ')}`);
					const connectResult = await openCandidatesConcurrent(candidateList);
					socket = connectResult.socket;
					candidate = connectResult.candidate;
					await writeFirstPacket(socket, data);
					log(`[反代连接] 成功连接到: ${candidate.hostname}:${candidate.port} (索引: ${candidate.index})`);
					proxyListIndex = candidate.index;
					return socket;
				} catch (err) {
					try { socket?.close?.() } catch (e) { }
					log(`[反代连接] 本批连接失败: ${err.message || err}`);
				}
			}
		}

		if (allowProxyFallback) return connectDirect(address, port, data, false);
		else {
			throw new Error('[反代连接] 所有反代连接失败，且未启用反代兜底，连接终止。');
		}
	}

	async function connecttoPry(allowSendFirstPacket = true) {
		if (remoteConnWrapper.connectingPromise) {
			await remoteConnWrapper.connectingPromise;
			return;
		}
		const { generation: currentGeneration, downlinkDrain } = beginTcpGeneration(remoteConnWrapper);

		let sendFirstPacketNow = false, currentFirstPacket = null;
		if (useTrojanProxy) {
			if (allowSendFirstPacket && !firstPacketSentViaProxy && effectiveByteLength(trojanProxyFirstPacket) > 0) {
				currentFirstPacket = trojanProxyFirstPacket;
				sendFirstPacketNow = effectiveByteLength(rawData) > 0;
			} else {
				currentFirstPacket = trojanProxyHandshake;
			}
		} else {
			sendFirstPacketNow = allowSendFirstPacket && !firstPacketSentViaProxy && effectiveByteLength(rawData) > 0;
			currentFirstPacket = sendFirstPacketNow ? rawData : null;
		}

		const currentConnectTask = (async () => {
			let newSocket = null;
			try {
				if (useTrojanProxy) {
					log(`[木马反代] 代理到: ${host}:${portNum}`);
					newSocket = await connectTrojanProxy(currentFirstPacket, tcpConnect, trojanProxyTarget);
				} else if (ctxProxyType === 'socks5') {
					log(`[SOCKS5代理] 代理到: ${host}:${portNum}`);
					newSocket = await socks5Connect(host, portNum, currentFirstPacket, tcpConnect, ctxProxyParams);
				} else if (ctxProxyType === 'http') {
					log(`[HTTP代理] 代理到: ${host}:${portNum}`);
					newSocket = await httpConnect(host, portNum, currentFirstPacket, false, tcpConnect, ctxProxyParams);
				} else if (ctxProxyType === 'https') {
					log(`[HTTPS代理] 代理到: ${host}:${portNum}`);
					newSocket = isIPHostname(ctxProxyParams.hostname)
						? await httpsConnect(host, portNum, currentFirstPacket, tcpConnect, ctxProxyParams)
						: await httpConnect(host, portNum, currentFirstPacket, true, tcpConnect, ctxProxyParams);
				} else if (ctxProxyType === 'turn') {
					log(`[TURN代理] 代理到: ${host}:${portNum}`);
					newSocket = await turnConnect(ctxProxyParams, host, portNum, tcpConnect);
					if (effectiveByteLength(currentFirstPacket) > 0) {
						const writer = newSocket.writable.getWriter();
						try { await writer.write(toUint8Array(currentFirstPacket)) }
						finally { try { writer.releaseLock() } catch (e) { } }
					}
				} else if (ctxProxyType === 'sstp') {
					log(`[SSTP代理] 代理到: ${host}:${portNum}`);
					newSocket = await sstpConnect(ctxProxyParams, host, portNum, tcpConnect);
					if (effectiveByteLength(currentFirstPacket) > 0) {
						const writer = newSocket.writable.getWriter();
						try { await writer.write(toUint8Array(currentFirstPacket)) }
						finally { try { writer.releaseLock() } catch (e) { } }
					}
				} else {
					log(`[反代连接] 代理到: ${host}:${portNum}`);
					const allProxyList = await resolveAddrPort(ctxProxyIP, host, yourUUID);
					newSocket = await connectProxyIP(`${BRAND_PROXYIP}.tp1.${BRAND_TP1_ID}.xyz`, 1, currentFirstPacket, allProxyList, ctxProxyFallback);
				}
				await installCurrentConnection(newSocket, currentGeneration, downlinkDrain);
				if (sendFirstPacketNow) firstPacketSentViaProxy = true;
			} catch (err) {
				try { newSocket?.close?.() } catch (e) { }
				if (remoteConnWrapper.generation === currentGeneration) {
					remoteConnWrapper.socket = null;
					closeSocketQuietly(ws);
					throw err;
				}
			}
		})();

		remoteConnWrapper.connectingPromise = currentConnectTask;
		try {
			await currentConnectTask;
		} finally {
			if (remoteConnWrapper.connectingPromise === currentConnectTask) {
				remoteConnWrapper.connectingPromise = null;
			}
		}
	}
	remoteConnWrapper.retryConnect = async () => connecttoPry(!firstPacketSentViaProxy);

	if (ctxProxyType && (ctxProxyGlobal || socks5Whitelist.some(p => new RegExp(`^${p.replace(/\*/g, '.*')}$`, 'i').test(host)))) {
		log(`[TCP转发] 启用 SOCKS5/HTTP/HTTPS/TURN/SSTP 全局代理`);
		try {
			await connecttoPry();
			if (connectOnly) return remoteConnWrapper.socket;
		} catch (err) {
			log(`[TCP转发] SOCKS5/HTTP/HTTPS/TURN/SSTP 代理连接失败: ${err.message}`);
			throw err;
		}
	} else {
		let directGeneration = remoteConnWrapper.generation;
		try {
			log(`[TCP转发] 尝试直连到: ${host}:${portNum}`);
			const generationConn = beginTcpGeneration(remoteConnWrapper);
			directGeneration = generationConn.generation;
			const initialSocket = await connectDirect(host, portNum, rawData, true);
			await installCurrentConnection(initialSocket, directGeneration, generationConn.downlinkDrain, async () => {
				if (remoteConnWrapper.generation !== directGeneration || remoteConnWrapper.socket !== initialSocket) return;
				await connecttoPry();
			});
			if (connectOnly) return initialSocket;
		} catch (err) {
			log(`[TCP转发] 直连 ${host}:${portNum} 失败: ${err.message}`);
			if (remoteConnWrapper.generation !== directGeneration) throw err;
			if (err instanceof Error && err.name === '预加载解析为空') {
				closeSocketQuietly(ws);
				throw err;
			}
			if (ws.readyState !== WebSocket.OPEN) throw err;
			await connecttoPry();
			if (connectOnly) return remoteConnWrapper.socket;
		}
	}
}

async function forwardataudp(udpChunk, webSocket, respHeader, request, responseWrapper = null) {
	const requestData = toUint8Array(udpChunk);
	const requestByteCount = requestData.byteLength;
	log(`[UDP转发] 收到 DNS 请求: ${requestByteCount}B -> 8.8.4.4:53`);
	try {
		const tcpConnect = createRequestTcpConnector(request);
		const tcpSocket = tcpConnect({ hostname: '8.8.4.4', port: 53 });
		let vlessHeader = respHeader;
		const writer = tcpSocket.writable.getWriter();
		await writer.write(requestData);
		log(`[UDP转发] DNS 请求已写入上游: ${requestByteCount}B`);
		writer.releaseLock();
		await tcpSocket.readable.pipeTo(new WritableStream({
			async write(chunk) {
				const rawResponse = toUint8Array(chunk);
				log(`[UDP转发] 收到 DNS 响应: ${rawResponse.byteLength}B`);
				const wrappedResult = responseWrapper ? await responseWrapper(rawResponse) : rawResponse;
				const sendFragments = Array.isArray(wrappedResult) ? wrappedResult : [wrappedResult];
				if (!sendFragments.length) return;
				if (webSocket.readyState !== WebSocket.OPEN) return;
				for (const fragment of sendFragments) {
					const forwardResponse = toUint8Array(fragment);
					if (!forwardResponse.byteLength) continue;
					if (vlessHeader) {
						const response = new Uint8Array(vlessHeader.length + forwardResponse.byteLength);
						response.set(vlessHeader, 0);
						response.set(forwardResponse, vlessHeader.length);
						await wsSendAndWait(webSocket, response.buffer);
						vlessHeader = null;
					} else {
						await wsSendAndWait(webSocket, forwardResponse);
					}
				}
			},
		}));
	} catch (error) {
		log(`[UDP转发] DNS 转发失败: ${error?.message || error}`);
	}
}

function closeSocketQuietly(socket) {
	try {
		if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
			socket.close();
		}
	} catch (error) { }
}

function formatIdentifier(arr, offset = 0) {
	const hex = [...arr.slice(offset, offset + 16)].map(b => b.toString(16).padStart(2, '0')).join('');
	return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}

async function wsSendAndWait(webSocket, payload) {
	const sendResult = webSocket.send(payload);
	if (sendResult && typeof sendResult.then === 'function') await sendResult;
}

// 定长环形缓冲：合包/拆包的最小单元，支持按条目取整批（copyCoalesceResult 时拷贝结果避免视图失效）
function createGrainBuffer(capacity, copyCoalesceResult = false) {
	let queue = [];
	let head = 0;
	let byteCount = 0;
	let coalesceBuffer = null;

	const isEmpty = () => head >= queue.length;
	const compressed = () => {
		if (head > 32 && head * 2 >= queue.length) {
			queue = queue.slice(head);
			head = 0;
		}
	};
	const take = () => {
		if (isEmpty()) return null;
		const item = queue[head];
		queue[head++] = undefined;
		byteCount -= item.chunk.byteLength;
		compressed();
		return item;
	};

	return {
		get byteCount() { return byteCount },
		get entryCount() { return queue.length - head },
		get isEmpty() { return isEmpty() },
		clear(processItem = null) {
			if (processItem) {
				for (let i = head; i < queue.length; i++) {
					if (queue[i]) processItem(queue[i]);
				}
			}
			queue = [];
			head = 0;
			byteCount = 0;
		},
		absorb(item) {
			if (!item?.chunk?.byteLength) return false;
			queue.push(item);
			byteCount += item.chunk.byteLength;
			return true;
		},
		coalesce() {
			const first = take();
			if (!first) return null;
			const items = [first];
			if (isEmpty() || first.chunk.byteLength >= capacity) return { chunk: first.chunk, items };

			let totalBytes = first.chunk.byteLength;
			let end = head;
			while (end < queue.length) {
				const nextBytes = totalBytes + queue[end].chunk.byteLength;
				if (nextBytes > capacity) break;
				totalBytes = nextBytes;
				end++;
			}
			if (end === head) return { chunk: first.chunk, items };

			const output = (coalesceBuffer ||= new Uint8Array(capacity));
			output.set(first.chunk, 0);
			let offset = first.chunk.byteLength;
			while (head < end) {
				const next = queue[head];
				queue[head++] = undefined;
				byteCount -= next.chunk.byteLength;
				items.push(next);
				output.set(next.chunk, offset);
				offset += next.chunk.byteLength;
			}
			compressed();
			const bundled = output.subarray(0, totalBytes);
			return { chunk: copyCoalesceResult ? bundled.slice() : bundled, items };
		}
	};
}

// 上行合包流：把零散写入攒到 UPLINK_COALESCE_TARGET_BYTES 再交给 socket，减少小包开销
function createUplinkCoalesceStream(targetBytes = UPLINK_COALESCE_TARGET_BYTES) {
	const identity = typeof IdentityTransformStream !== 'undefined'
		? new IdentityTransformStream()
		: new TransformStream();
	const writer = identity.writable.getWriter();
	const buffer = new Uint8Array(targetBytes);
	let bufferLength = 0;
	let timer = null;
	let inflightWrites = null;
	let flushChain = Promise.resolve();

	const cleanupTimer = () => {
		if (timer) {
			clearTimeout(timer);
			timer = null;
		}
	};

	const serialWrite = async (chunk) => {
		if (inflightWrites) await inflightWrites;
		inflightWrites = writer.write(chunk);
		try { await inflightWrites } finally { inflightWrites = null; }
	};

	const flush = async () => {
		if (bufferLength) {
			const chunk = buffer.slice(0, bufferLength);
			bufferLength = 0;
			await serialWrite(chunk);
		}
	};

	const queueFlush = () => {
		flushChain = flushChain.then(() => flush()).catch(() => { });
	};

	const startTimer = () => {
		if (timer) return;
		timer = setTimeout(() => {
			timer = null;
			queueFlush();
		}, 1);
	};

	return {
		readable: identity.readable,
		write: async (chunk) => {
			const data = toUint8Array(chunk);
			if (!data.byteLength) return;
			if (data.byteLength >= targetBytes) {
				cleanupTimer();
				if (bufferLength) await flush();
				await serialWrite(data);
				return;
			}
			if (bufferLength + data.byteLength >= targetBytes) {
				const output = new Uint8Array(bufferLength + data.byteLength);
				output.set(buffer.subarray(0, bufferLength), 0);
				output.set(data, bufferLength);
				bufferLength = 0;
				cleanupTimer();
				await serialWrite(output);
			} else {
				buffer.set(data, bufferLength);
				bufferLength += data.byteLength;
				startTimer();
			}
		},
		end: async () => {
			cleanupTimer();
			try {
				await flushChain;
				await flush();
				await writer.close();
			} finally {
				try { writer.releaseLock() } catch (e) { }
			}
		}
	};
}

// 上行写入队列：串行化写入 + 断线重连钩子；超 UPLINK_QUEUE_MAX_* 时主动关连接防内存膨胀
function createUplinkWriteQueue({ getWriter, getConnectTask = null, releaseWriter, retryConnect, closeConnection, queueName = '上行队列' }) {
	const grain = createGrainBuffer(UPLINK_COALESCE_TARGET_BYTES);
	let draining = false;
	let closed = false;
	let idleResolvers = [];
	let activeCompletions = null;

	const settleCompletions = (completions, err = null) => {
		if (!completions) return;
		for (const completion of completions) {
			if (err) completion.reject(err);
			else completion.resolve();
		}
	};

	const resolveIdle = () => {
		if (grain.byteCount || draining || !idleResolvers.length) return;
		const resolvers = idleResolvers;
		idleResolvers = [];
		for (const resolve of resolvers) resolve();
	};

	const clear = (err = null) => {
		const closeErr = err || (closed ? new Error(`${queueName}: queue closed`) : null);
		if (closeErr) {
			grain.clear(item => settleCompletions(item.completions, closeErr));
			settleCompletions(activeCompletions, closeErr);
			activeCompletions = null;
		} else grain.clear();
		resolveIdle();
	};

	const bundle = () => {
		const packed = grain.coalesce();
		if (!packed) return null;
		let allowRetry = true;
		let completions = null;
		for (const item of packed.items) {
			allowRetry = allowRetry && item.allowRetry;
			if (item.completions) completions = completions ? completions.concat(item.completions) : item.completions;
		}
		return { chunk: packed.chunk, allowRetry, completions };
	};

	const waitForAvailableWriter = async () => {
		let writer = getWriter();
		if (writer) return writer;
		const connectionTask = getConnectTask?.();
		if (connectionTask) await connectionTask;
		return getWriter();
	};

	const drain = async () => {
		if (draining || closed) return;
		draining = true;
		try {
			for (; ;) {
				if (closed) break;
				const item = bundle();
				if (!item) break;
				const completions = item.completions || null;
				activeCompletions = completions;
				try {
					let writer = await waitForAvailableWriter();
					if (closed) break;
					if (!writer) throw new Error(`${queueName}: remote writer unavailable`);
					try {
						await writer.write(item.chunk);
					} catch (err) {
						releaseWriter?.();
						if (closed) break;
						if (!item.allowRetry || typeof retryConnect !== 'function') throw err;
						await retryConnect();
						if (closed) break;
						writer = getWriter();
						if (!writer) throw err;
						await writer.write(item.chunk);
					}
					settleCompletions(completions);
				} catch (err) {
					settleCompletions(completions, err);
					throw err;
				} finally {
					if (activeCompletions === completions) activeCompletions = null;
				}
			}
		} catch (err) {
			closed = true;
			clear(err);
			log(`[${queueName}] 写入失败: ${err?.message || err}`);
			try { closeConnection?.(err) } catch (_) { }
		} finally {
			draining = false;
			if (!closed && !grain.isEmpty) drain();
			else resolveIdle();
		}
	};

	const enqueue = (data, allowRetry = true, waitForFlush = false) => {
		if (closed) return false;
		// 首包解析阶段既没有 writer 也没有连接任务；返回 false 交给上层继续协议解析。
		// 已建立会话的重拨阶段则先收纳，drain 会等待新 writer，避免数据被误当成首包。
		if (!getWriter() && !getConnectTask?.()) return false;
		const chunk = toUint8Array(data);
		if (!chunk.byteLength) return true;
		const nextBytes = grain.byteCount + chunk.byteLength;
		const nextItems = grain.entryCount + 1;
		if (nextBytes > UPLINK_QUEUE_MAX_BYTES || nextItems > UPLINK_QUEUE_MAX_ITEMS) {
			closed = true;
			const err = Object.assign(new Error(`${queueName}: upload queue overflow (${nextBytes}B/${nextItems})`), { isQueueOverflow: true });
			clear(err);
			log(`[${queueName}] 队列超限，关闭连接`);
			try { closeConnection?.(err) } catch (_) { }
			throw err;
		}
		let completionPromise = null;
		let completions = null;
		if (waitForFlush) {
			completions = [];
			completionPromise = new Promise((resolve, reject) => completions.push({ resolve, reject }));
		}
		grain.absorb({ chunk, allowRetry, completions });
		if (!draining) drain();
		return waitForFlush ? completionPromise.then(() => true) : true;
	};

	return {
		write(data, allowRetry = true) {
			return enqueue(data, allowRetry, false);
		},
		writeAndWait(data, allowRetry = true) {
			return enqueue(data, allowRetry, true);
		},
		async waitIdle() {
			if (!grain.byteCount && !draining) return;
			await new Promise(resolve => idleResolvers.push(resolve));
		},
		clear() {
			closed = true;
			clear();
		}
	};
}

// 下行 Grain 发送器：把 remote 读到的数据按 DOWNLINK_GRAIN_* 阈值分帧写回 WebSocket
function createDownlinkGrainSender(webSocket, headerData = null, isActive = null) {
	const packetCap = DOWNLINK_GRAIN_CHUNK_BYTES;
	const tailBytes = DOWNLINK_GRAIN_TAIL_THRESHOLD;
	const grain = createGrainBuffer(packetCap, true);
	let header = typeof headerData === 'function' ? null : headerData;
	const getResponseHeader = typeof headerData === 'function' ? headerData : () => {
		const value = header;
		header = null;
		return value;
	};
	let flushTimer = null;
	let generation = 0;
	let scheduledGeneration = 0;
	let waitRounds = 0;
	let flushPromise = null;
	let directSendPromise = null;
	let forceDrain = false;
	let stopStarted = false;
	let activeSendCount = 0;
	let activeDirectSendCount = 0;
	let activeSendError = null;
	let activeSendWaiters = [];
	const waitForActiveSends = () => {
		if (!activeSendCount && !activeDirectSendCount) return Promise.resolve();
		return new Promise(resolve => activeSendWaiters.push(resolve));
	};
	const markSendDone = () => {
		if (activeSendCount || activeDirectSendCount || !activeSendWaiters.length) return;
		const resolvers = activeSendWaiters;
		activeSendWaiters = [];
		for (const resolve of resolvers) resolve();
	};
	const checkActiveSendError = () => {
		if (!activeSendError) return;
		const err = activeSendError;
		grain.clear();
		throw err;
	};
	const currentSenderActive = () => forceDrain || !isActive || isActive();
	const closeActiveConnections = () => {
		if (currentSenderActive()) closeSocketQuietly(webSocket);
	};

	const sendRawChunk = async (chunk) => {
		if (!currentSenderActive()) return;
		if (webSocket.readyState !== WebSocket.OPEN) throw new Error('ws.readyState is not open');
		chunk = extraRespHeader(chunk);
		await wsSendAndWait(webSocket, chunk);
	};

	const serialSendRawChunk = async (chunk) => {
		while (directSendPromise) await directSendPromise;
		const sendTask = sendRawChunk(chunk);
		directSendPromise = sendTask;
		try { await sendTask }
		finally {
			if (directSendPromise === sendTask) directSendPromise = null;
		}
	};

	const extraRespHeader = (chunk) => {
		const responseHeader = getResponseHeader();
		if (!responseHeader) return chunk;
		const merged = new Uint8Array(responseHeader.length + chunk.byteLength);
		merged.set(responseHeader, 0);
		merged.set(chunk, responseHeader.length);
		return merged;
	};

	const flush = async () => {
		while (flushPromise) await flushPromise;
		if (flushTimer) clearTimeout(flushTimer);
		flushTimer = null;
		waitRounds = 0;
		if (!currentSenderActive()) {
			grain.clear();
			return;
		}
		const sendTask = (async () => {
			for (; ;) {
				if (!currentSenderActive()) {
					grain.clear();
					break;
				}
				const packed = grain.coalesce();
				if (!packed) break;
				await serialSendRawChunk(packed.chunk);
			}
		})();
		flushPromise = sendTask.catch(err => {
			activeSendError ||= err;
			throw err;
		}).finally(() => { flushPromise = null });
		return flushPromise;
	};

	const scheduleFlush = () => {
		if (!currentSenderActive()) {
			grain.clear();
			return;
		}
		if (grain.isEmpty || flushTimer) return;
		if (grain.byteCount >= packetCap || packetCap - grain.byteCount < tailBytes) {
			flush().catch(closeActiveConnections);
			return;
		}
		flushTimer = setTimeout(() => {
			flushTimer = null;
			if (!currentSenderActive()) {
				grain.clear();
				return;
			}
			if (grain.isEmpty) return;
			if (grain.byteCount >= packetCap || packetCap - grain.byteCount < tailBytes) {
				flush().catch(closeActiveConnections);
				return;
			}
			if (waitRounds < DOWNLINK_GRAIN_MAX_WAIT_ROUNDS && (generation !== scheduledGeneration || grain.byteCount < DOWNLINK_GRAIN_LOW_WATER_BYTES)) {
				waitRounds++;
				scheduledGeneration = generation;
				scheduleFlush();
				return;
			}
			flush().catch(closeActiveConnections);
		}, 1);
	};

	return {
		async sendDirectly(data) {
			if (stopStarted || !currentSenderActive()) return;
			activeDirectSendCount++;
			try {
				const chunk = toUint8Array(data);
				if (!chunk.byteLength) return;
				await serialSendRawChunk(chunk);
			} catch (err) {
				activeSendError ||= err;
				throw err;
			} finally {
				activeDirectSendCount--;
				markSendDone();
			}
		},
		async send(data) {
			if (stopStarted || !currentSenderActive()) return;
			activeSendCount++;
			try {
				const chunk = toUint8Array(data);
				if (!chunk.byteLength) return;
				let offset = 0;
				const totalBytes = chunk.byteLength;
				while (offset < totalBytes) {
					const remainingBytes = totalBytes - offset;
					if (grain.isEmpty && remainingBytes >= packetCap) {
						const sendBytes = Math.min(packetCap, remainingBytes);
						const view = offset || sendBytes !== totalBytes ? chunk.subarray(offset, offset + sendBytes) : chunk;
						await serialSendRawChunk(view);
						offset += sendBytes;
						continue;
					}
					const copyBytes = Math.min(packetCap - grain.byteCount, totalBytes - offset);
					if (!copyBytes) {
						await flush();
						continue;
					}
					grain.absorb({ chunk: offset || copyBytes !== totalBytes ? chunk.subarray(offset, offset + copyBytes) : chunk });
					offset += copyBytes;
					generation++;
					if (grain.byteCount >= packetCap || packetCap - grain.byteCount < tailBytes) await flush();
					else scheduleFlush();
				}
			} catch (err) {
				activeSendError ||= err;
				throw err;
			} finally {
				activeSendCount--;
				markSendDone();
			}
		},
		flush,
		async stopAndFlush() {
			if (stopStarted) {
				await waitForActiveSends();
				while (directSendPromise) await directSendPromise;
				checkActiveSendError();
				await flush();
				return;
			}
			stopStarted = true;
			forceDrain = true;
			if (flushTimer) clearTimeout(flushTimer);
			flushTimer = null;
			await waitForActiveSends();
			while (directSendPromise) await directSendPromise;
			checkActiveSendError();
			await flush();
		}
	};
}

// 双向管道：remoteSocket ↔ WebSocket 对拷，下行经 Grain 分帧；retryFunc 由 forwardataTCP 注入断线重连
async function connectStreams(remoteSocket, webSocket, headerData, retryFunc, isCurrentSocket = null, remoteConnWrapper = null) {
	let header = headerData, hasData = false, reader, useBYOB = false, readError = null;
	const byobReadLimit = 64 * 1024;
	const isCurrentConnectionValid = () => !isCurrentSocket || isCurrentSocket();
	const downlinkSender = createDownlinkGrainSender(webSocket, header, isCurrentConnectionValid);
	header = null;
	const downlinkController = { stopAndFlush: () => downlinkSender.stopAndFlush() };
	if (remoteConnWrapper) remoteConnWrapper.downlinkController = downlinkController;
	try { remoteSocket.closed?.catch?.(() => { }) } catch (e) { }

	try { reader = remoteSocket.readable.getReader({ mode: 'byob' }); useBYOB = true }
	catch (e) { reader = remoteSocket.readable.getReader() }

	try {
		if (!useBYOB) {
			while (true) {
				const { done, value } = await reader.read();
				if (!isCurrentConnectionValid()) break;
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (value.byteLength >= DOWNLINK_GRAIN_CHUNK_BYTES) {
					await downlinkSender.flush();
					await downlinkSender.sendDirectly(value);
				} else {
					await downlinkSender.send(value);
				}
			}
		} else {
			let readBuffer = new ArrayBuffer(byobReadLimit);
			while (true) {
				const { done, value } = await reader.read(new Uint8Array(readBuffer, 0, byobReadLimit));
				if (!isCurrentConnectionValid()) break;
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (value.byteLength >= DOWNLINK_GRAIN_CHUNK_BYTES) {
					await downlinkSender.flush();
					await downlinkSender.sendDirectly(value);
					readBuffer = new ArrayBuffer(byobReadLimit);
				} else {
					await downlinkSender.send(value.slice());
					readBuffer = value.buffer.byteLength >= byobReadLimit ? value.buffer : new ArrayBuffer(byobReadLimit);
				}
			}
		}
		if (isCurrentConnectionValid()) await downlinkSender.flush();
	} catch (err) { readError = err }
	finally {
		if (isCurrentConnectionValid() && webSocket.readyState === WebSocket.OPEN) {
			try { await downlinkSender.stopAndFlush() } catch (err) { readError ||= err }
		}
		if (remoteConnWrapper?.downlinkController === downlinkController) remoteConnWrapper.downlinkController = null;
		try { await reader.cancel() } catch (e) { }
		try { reader.releaseLock() } catch (e) { }
		try { remoteSocket.close() } catch (e) { }
	}
	if (!hasData && retryFunc && webSocket.readyState === WebSocket.OPEN && isCurrentConnectionValid()) {
		try {
			await retryFunc();
			return;
		} catch (err) {
			readError ||= err;
		}
	}
	if (!isCurrentConnectionValid()) return;
	if (readError) log(`[TCP下行] 读取失败: ${readError?.message || readError}`);
	closeSocketQuietly(webSocket);
}

function isSpeedTestSite(hostname) {
	const speedTestDomains = ['speed.cloudflare.com', 'cp.cloudflare.com'];
	hostname = hostname.toLowerCase();
	return speedTestDomains.some(domain => hostname === domain || hostname.endsWith('.' + domain));
}

function buildLocal204Response(respHeader = null) {
	const local204Response = new TextEncoder().encode(
		'HTTP/1.1 204 No Content\r\n' +
		'Content-Length: 0\r\n' +
		'Connection: close\r\n' +
		'\r\n'
	);
	if (effectiveByteLength(respHeader) === 0) return local204Response;
	const protocolRespHeader = toUint8Array(respHeader);
	const response = new Uint8Array(protocolRespHeader.byteLength + local204Response.byteLength);
	response.set(protocolRespHeader, 0);
	response.set(local204Response, protocolRespHeader.byteLength);
	log(`[TCP转发] 构造本地204响应: ${response.byteLength}B`);
	return response;
}

function buildWsLocal204Response(respHeader = null) {
	const wsLocal204Response = new TextEncoder().encode(
		'HTTP/1.1 204 No Content\r\n' +
		'Content-Length: 0\r\n' +
		'Connection: keep-alive\r\n' +
		'\r\n'
	);
	if (effectiveByteLength(respHeader) === 0) return wsLocal204Response;
	const protocolRespHeader = toUint8Array(respHeader);
	const response = new Uint8Array(protocolRespHeader.byteLength + wsLocal204Response.byteLength);
	response.set(protocolRespHeader, 0);
	response.set(wsLocal204Response, protocolRespHeader.byteLength);
	return response;
}

///////////////////////////////////////////////////////链式代理客户端（SOCKS5 / HTTP / HTTPS CONNECT）///////////////////////////////////////////////
async function socks5Connect(targetHost, targetPort, initialData, tcpConnect, parsedSocks5) {
	const { username, password, hostname, port } = parsedSocks5 || {};
	const socket = tcpConnect({ hostname, port }), writer = socket.writable.getWriter(), reader = socket.readable.getReader();
	try {
		const authMethods = username && password ? new Uint8Array([0x05, 0x02, 0x00, 0x02]) : new Uint8Array([0x05, 0x01, 0x00]);
		await writer.write(authMethods);
		let response = await reader.read();
		if (response.done || response.value.byteLength < 2) throw new Error('S5 method selection failed');

		const selectedMethod = new Uint8Array(response.value)[1];
		if (selectedMethod === 0x02) {
			if (!username || !password) throw new Error('S5 requires authentication');
			const userBytes = new TextEncoder().encode(username), passBytes = new TextEncoder().encode(password);
			const authPacket = new Uint8Array([0x01, userBytes.length, ...userBytes, passBytes.length, ...passBytes]);
			await writer.write(authPacket);
			response = await reader.read();
			if (response.done || new Uint8Array(response.value)[1] !== 0x00) throw new Error('S5 authentication failed');
		} else if (selectedMethod !== 0x00) throw new Error(`S5 unsupported auth method: ${selectedMethod}`);

		const hostBytes = new TextEncoder().encode(targetHost);
		const connectPacket = new Uint8Array([0x05, 0x01, 0x00, 0x03, hostBytes.length, ...hostBytes, targetPort >> 8, targetPort & 0xff]);
		await writer.write(connectPacket);
		response = await reader.read();
		if (response.done || new Uint8Array(response.value)[1] !== 0x00) throw new Error('S5 connection failed');

		if (effectiveByteLength(initialData) > 0) await writer.write(initialData);
		writer.releaseLock(); reader.releaseLock();
		return socket;
	} catch (error) {
		try { writer.releaseLock() } catch (e) { }
		try { reader.releaseLock() } catch (e) { }
		try { socket.close() } catch (e) { }
		throw error;
	}
}

async function httpConnect(targetHost, targetPort, initialData, httpsProxy = false, tcpConnect, parsedSocks5) {
	const { username, password, hostname, port } = parsedSocks5 || {};
	const socket = httpsProxy
		? tcpConnect({ hostname, port }, { secureTransport: 'on', allowHalfOpen: false })
		: tcpConnect({ hostname, port });
	const writer = socket.writable.getWriter(), reader = socket.readable.getReader();
	const encoder = new TextEncoder();
	const decoder = new TextDecoder();
	try {
		if (httpsProxy) await socket.opened;

		const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
		const request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
		await writer.write(encoder.encode(request));
		writer.releaseLock();

		let responseBuffer = new Uint8Array(0), headerEndIndex = -1, bytesRead = 0;
		while (headerEndIndex === -1 && bytesRead < 8192) {
			const { done, value } = await reader.read();
			if (done || !value) throw new Error(`${httpsProxy ? 'HTTPS' : 'HTTP'} 代理在返回 CONNECT 响应前关闭连接`);
			responseBuffer = new Uint8Array([...responseBuffer, ...value]);
			bytesRead = responseBuffer.length;
			const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
			if (crlfcrlf !== -1) headerEndIndex = crlfcrlf + 4;
		}

		if (headerEndIndex === -1) throw new Error('代理 CONNECT 响应头过长或无效');
		const statusMatch = decoder.decode(responseBuffer.slice(0, headerEndIndex)).split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/);
		const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
		if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`Connection failed: HTTP ${statusCode}`);

		reader.releaseLock();

		if (effectiveByteLength(initialData) > 0) {
			const remoteWriter = socket.writable.getWriter();
			await remoteWriter.write(initialData);
			remoteWriter.releaseLock();
		}

		// CONNECT 响应头后可能夹带隧道数据，先回灌到可读流，避免首包被吞。
		if (bytesRead > headerEndIndex) {
			const { readable, writable } = new TransformStream();
			const transformWriter = writable.getWriter();
			await transformWriter.write(responseBuffer.subarray(headerEndIndex, bytesRead));
			transformWriter.releaseLock();
			socket.readable.pipeTo(writable).catch(() => { });
			return { readable, writable: socket.writable, closed: socket.closed, close: () => socket.close() };
		}

		return socket;
	} catch (error) {
		try { writer.releaseLock() } catch (e) { }
		try { reader.releaseLock() } catch (e) { }
		try { socket.close() } catch (e) { }
		throw error;
	}
}

async function httpsConnect(targetHost, targetPort, initialData, tcpConnect, parsedSocks5) {
	const { username, password, hostname, port } = parsedSocks5 || {};
	const encoder = new TextEncoder();
	const decoder = new TextDecoder();
	let tlsSocket = null;
	const tlsServerName = isIPHostname(hostname) ? '' : stripIPv6Brackets(hostname);
	const openHttpsProxyTls = async (allowChacha = false) => {
		const proxySocket = tcpConnect({ hostname, port });
		try {
			await proxySocket.opened;
			const socket = new TlsClient(proxySocket, { serverName: tlsServerName, insecure: true, allowChacha });
			await socket.handshake();
			log(`[HTTPS代理] TLS版本: ${socket.isTls13 ? '1.3' : '1.2'} | Cipher: 0x${socket.cipherSuite.toString(16)}${socket.cipherConfig?.chacha ? ' (ChaCha20)' : ' (AES-GCM)'}`);
			return socket;
		} catch (error) {
			try { proxySocket.close() } catch (e) { }
			throw error;
		}
	};
	try {
		try {
			tlsSocket = await openHttpsProxyTls(false);
		} catch (error) {
			if (!/cipher|handshake|TLS Alert|ServerHello|Finished|Unsupported|Missing TLS/i.test(error?.message || `${error || ''}`)) throw error;
			log(`[HTTPS代理] AES-GCM TLS 握手失败，回退 ChaCha20 兼容模式: ${error?.message || error}`);
			tlsSocket = await openHttpsProxyTls(true);
		}

		const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
		const request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
		await tlsSocket.write(encoder.encode(request));

		let responseBuffer = new Uint8Array(0), headerEndIndex = -1, bytesRead = 0;
		while (headerEndIndex === -1 && bytesRead < 8192) {
			const value = await tlsSocket.read();
			if (!value) throw new Error('HTTPS 代理在返回 CONNECT 响应前关闭连接');
			responseBuffer = concatByteChunks(responseBuffer, value);
			bytesRead = responseBuffer.length;
			const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
			if (crlfcrlf !== -1) headerEndIndex = crlfcrlf + 4;
		}

		if (headerEndIndex === -1) throw new Error('HTTPS 代理 CONNECT 响应头过长或无效');
		const statusMatch = decoder.decode(responseBuffer.slice(0, headerEndIndex)).split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/);
		const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
		if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`Connection failed: HTTP ${statusCode}`);

		if (effectiveByteLength(initialData) > 0) await tlsSocket.write(toUint8Array(initialData));
		const bufferedData = bytesRead > headerEndIndex ? responseBuffer.subarray(headerEndIndex, bytesRead) : null;
		let closedSettled = false, resolveClosed, rejectClosed;
		const settleClosed = (settle, value) => {
			if (!closedSettled) {
				closedSettled = true;
				settle(value);
			}
		};
		const closed = new Promise((resolve, reject) => {
			resolveClosed = resolve;
			rejectClosed = reject;
		});
		const close = () => {
			try { tlsSocket.close() } catch (e) { }
			settleClosed(resolveClosed);
		};
		const readable = new ReadableStream({
			async start(controller) {
				try {
					if (effectiveByteLength(bufferedData) > 0) controller.enqueue(bufferedData);
					while (true) {
						const data = await tlsSocket.read();
						if (!data) break;
						if (data.byteLength > 0) controller.enqueue(data);
					}
					try { controller.close() } catch (e) { }
					settleClosed(resolveClosed);
				} catch (error) {
					try { controller.error(error) } catch (e) { }
					settleClosed(rejectClosed, error);
				}
			},
			cancel() {
				close();
			}
		});
		const writable = new WritableStream({
			async write(chunk) {
				await tlsSocket.write(toUint8Array(chunk));
			},
			close,
			abort(error) {
				close();
				if (error) settleClosed(rejectClosed, error);
			}
		});
		return { readable, writable, closed, close };
	} catch (error) {
		try { tlsSocket?.close() } catch (e) { }
		throw error;
	}
}

function createRequestTcpConnector(request) {
	const requestObj = /** @type {any} */ (request);
	const fetcher = requestObj?.fetcher;
	if (!fetcher || typeof fetcher.connect !== 'function') throw new Error('request.fetcher.connect unavailable');
	return (options, init) => init === undefined ? fetcher.connect(options) : fetcher.connect(options, init);
}
////////////////////////////////////////////自研 TLS 客户端（TLSClient by: @Alexandre_Kojeve，供 HTTPS 链式代理握手）////////////////////////////////////////////////
const TLS_VERSION_10 = 769, TLS_VERSION_12 = 771, TLS_VERSION_13 = 772;
const CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20, CONTENT_TYPE_ALERT = 21, CONTENT_TYPE_HANDSHAKE = 22, CONTENT_TYPE_APPLICATION_DATA = 23;
const HANDSHAKE_TYPE_CLIENT_HELLO = 1, HANDSHAKE_TYPE_SERVER_HELLO = 2, HANDSHAKE_TYPE_NEW_SESSION_TICKET = 4, HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS = 8, HANDSHAKE_TYPE_CERTIFICATE = 11, HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 12, HANDSHAKE_TYPE_CERTIFICATE_REQUEST = 13, HANDSHAKE_TYPE_SERVER_HELLO_DONE = 14, HANDSHAKE_TYPE_CERTIFICATE_VERIFY = 15, HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 16, HANDSHAKE_TYPE_FINISHED = 20, HANDSHAKE_TYPE_KEY_UPDATE = 24;
const EXT_SERVER_NAME = 0, EXT_SUPPORTED_GROUPS = 10, EXT_EC_POINT_FORMATS = 11, EXT_SIGNATURE_ALGORITHMS = 13, EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16, EXT_SUPPORTED_VERSIONS = 43, EXT_PSK_KEY_EXCHANGE_MODES = 45, EXT_KEY_SHARE = 51;

const ALERT_CLOSE_NOTIFY = 0, ALERT_LEVEL_WARNING = 1, ALERT_UNRECOGNIZED_NAME = 112;
const shouldIgnoreTlsAlert = fragment => fragment?.[0] === ALERT_LEVEL_WARNING && fragment?.[1] === ALERT_UNRECOGNIZED_NAME;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const EMPTY_BYTES = new Uint8Array(0);

const CIPHER_SUITES_BY_ID = new Map([
	[4865, { id: 4865, keyLen: 16, ivLen: 12, hash: "SHA-256", tls13: !0 }],
	[4866, { id: 4866, keyLen: 32, ivLen: 12, hash: "SHA-384", tls13: !0 }],
	[4867, { id: 4867, keyLen: 32, ivLen: 12, hash: "SHA-256", tls13: !0, chacha: !0 }],
	[49199, { id: 49199, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE" }],
	[49200, { id: 49200, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE" }],
	[52392, { id: 52392, keyLen: 32, ivLen: 12, hash: "SHA-256", kex: "ECDHE", chacha: !0 }],
	[49195, { id: 49195, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE" }],
	[49196, { id: 49196, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE" }],
	[52393, { id: 52393, keyLen: 32, ivLen: 12, hash: "SHA-256", kex: "ECDHE", chacha: !0 }]
]);
const GROUPS_BY_ID = new Map([[29, "X25519"], [23, "P-256"]]);
const SUPPORTED_SIGNATURE_ALGORITHMS = [2052, 2053, 2054, 1025, 1281, 1537, 1027, 1283, 1539];

const tlsBytes = (...parts) => {
	const flattenBytes = values => values.flatMap(value => value instanceof Uint8Array ? [...value] : Array.isArray(value) ? flattenBytes(value) : "number" == typeof value ? [value] : []);
	return new Uint8Array(flattenBytes(parts))
};
const uint16be = value => [value >> 8 & 255, 255 & value];
const readUint16 = (buffer, offset) => buffer[offset] << 8 | buffer[offset + 1];
const readUint24 = (buffer, offset) => buffer[offset] << 16 | buffer[offset + 1] << 8 | buffer[offset + 2];
const concatBytes = (...chunks) => {
	const nonEmptyChunks = chunks.filter((chunk => chunk && chunk.length > 0)),
		length = nonEmptyChunks.reduce(((total, chunk) => total + chunk.length), 0),
		result = new Uint8Array(length);
	let offset = 0;
	for (const chunk of nonEmptyChunks) result.set(chunk, offset), offset += chunk.length;
	return result
};
const randomBytes = length => crypto.getRandomValues(new Uint8Array(length));
const constantTimeEqual = (left, right) => {
	if (!left || !right || left.length !== right.length) return !1;
	let diff = 0; for (let index = 0; index < left.length; index++) diff |= left[index] ^ right[index];
	return 0 === diff
};
const hashByteLength = hash => "SHA-512" === hash ? 64 : "SHA-384" === hash ? 48 : 32;
async function hmac(hash, key, data) {
	const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash }, !1, ["sign"]);
	return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, data))
}
async function digestBytes(hash, data) { return new Uint8Array(await crypto.subtle.digest(hash, data)) }
async function tls12Prf(secret, label, seed, length, hash = "SHA-256") {
	const labelSeed = concatBytes(textEncoder.encode(label), seed);
	let output = new Uint8Array(0),
		currentA = labelSeed;
	for (; output.length < length;) {
		currentA = await hmac(hash, secret, currentA);
		const block = await hmac(hash, secret, concatBytes(currentA, labelSeed));
		output = concatBytes(output, block)
	}
	return output.slice(0, length)
}
async function hkdfExtract(hash, salt, inputKeyMaterial) {
	return salt && salt.length || (salt = new Uint8Array(hashByteLength(hash))), hmac(hash, salt, inputKeyMaterial)
}
async function hkdfExpandLabel(hash, secret, label, context, length) {
	const fullLabel = textEncoder.encode("tls13 " + label);
	return async function (hash, secret, info, length) {
		const hashLen = hashByteLength(hash),
			roundCount = Math.ceil(length / hashLen);
		let output = new Uint8Array(0),
			previousBlock = new Uint8Array(0);
		for (let round = 1; round <= roundCount; round++) previousBlock = await hmac(hash, secret, concatBytes(previousBlock, info, [round])), output = concatBytes(output, previousBlock);
		return output.slice(0, length)
	}(hash, secret, tlsBytes(uint16be(length), fullLabel.length, fullLabel, context.length, context), length)
}
async function generateKeyShare(group = "P-256") {
	const algorithm = "X25519" === group ? { name: "X25519" } : { name: "ECDH", namedCurve: group };
	const keyPair = /** @type {CryptoKeyPair} */ (await crypto.subtle.generateKey(algorithm, !0, ["deriveBits"]));
	const publicKeyRaw = /** @type {ArrayBuffer} */ (await crypto.subtle.exportKey("raw", keyPair.publicKey));
	return { keyPair, publicKeyRaw: new Uint8Array(publicKeyRaw) }
}
async function deriveSharedSecret(privateKey, peerPublicKey, group = "P-256") {
	const algorithm = "X25519" === group ? { name: "X25519" } : { name: "ECDH", namedCurve: group },
		peerKey = await crypto.subtle.importKey("raw", peerPublicKey, algorithm, !1, []),
		bits = "P-384" === group ? 384 : "P-521" === group ? 528 : 256;
	return new Uint8Array(await crypto.subtle.deriveBits(/** @type {any} */({ name: algorithm.name, public: peerKey }), privateKey, bits))
}
async function importAesGcmKey(key, usages) { return crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, !1, usages) }
async function aesGcmEncryptWithKey(cryptoKey, initializationVector, plaintext, additionalData) {
	return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: initializationVector, additionalData, tagLength: 128 }, cryptoKey, plaintext))
}
async function aesGcmDecryptWithKey(cryptoKey, initializationVector, ciphertext, additionalData) {
	return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: initializationVector, additionalData, tagLength: 128 }, cryptoKey, ciphertext))
}

function rotateLeft32(value, bits) { return (value << bits | value >>> 32 - bits) >>> 0 }

function chachaQuarterRound(state, indexA, indexB, indexC, indexD) {
	state[indexA] = state[indexA] + state[indexB] >>> 0, state[indexD] = rotateLeft32(state[indexD] ^ state[indexA], 16), state[indexC] = state[indexC] + state[indexD] >>> 0, state[indexB] = rotateLeft32(state[indexB] ^ state[indexC], 12), state[indexA] = state[indexA] + state[indexB] >>> 0, state[indexD] = rotateLeft32(state[indexD] ^ state[indexA], 8), state[indexC] = state[indexC] + state[indexD] >>> 0, state[indexB] = rotateLeft32(state[indexB] ^ state[indexC], 7)
}

function chacha20Block(key, counter, nonce) {
	const state = new Uint32Array(16);
	state[0] = 1634760805, state[1] = 857760878, state[2] = 2036477234, state[3] = 1797285236;
	const keyView = new DataView(key.buffer, key.byteOffset, key.byteLength);
	for (let wordIndex = 0; wordIndex < 8; wordIndex++) state[4 + wordIndex] = keyView.getUint32(4 * wordIndex, !0);
	state[12] = counter;
	const nonceView = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
	state[13] = nonceView.getUint32(0, !0), state[14] = nonceView.getUint32(4, !0), state[15] = nonceView.getUint32(8, !0);
	const workingState = new Uint32Array(state);
	for (let round = 0; round < 10; round++) chachaQuarterRound(workingState, 0, 4, 8, 12), chachaQuarterRound(workingState, 1, 5, 9, 13), chachaQuarterRound(workingState, 2, 6, 10, 14), chachaQuarterRound(workingState, 3, 7, 11, 15), chachaQuarterRound(workingState, 0, 5, 10, 15), chachaQuarterRound(workingState, 1, 6, 11, 12), chachaQuarterRound(workingState, 2, 7, 8, 13), chachaQuarterRound(workingState, 3, 4, 9, 14);
	for (let wordIndex = 0; wordIndex < 16; wordIndex++) workingState[wordIndex] = workingState[wordIndex] + state[wordIndex] >>> 0;
	return new Uint8Array(workingState.buffer.slice(0))
}

function chacha20Xor(key, nonce, data) {
	const output = new Uint8Array(data.length);
	let counter = 1;
	for (let offset = 0; offset < data.length; offset += 64) {
		const block = chacha20Block(key, counter++, nonce),
			blockLength = Math.min(64, data.length - offset);
		for (let index = 0; index < blockLength; index++) output[offset + index] = data[offset + index] ^ block[index]
	}
	return output
}

function poly1305Mac(key, message) {
	const rKey = function (rBytes) {
		const clamped = new Uint8Array(rBytes);
		return clamped[3] &= 15, clamped[7] &= 15, clamped[11] &= 15, clamped[15] &= 15, clamped[4] &= 252, clamped[8] &= 252, clamped[12] &= 252, clamped
	}(key.slice(0, 16)),
		sKey = key.slice(16, 32);
	let accumulator = [0n, 0n, 0n, 0n, 0n];
	const rLimbs = [0x3ffffffn & BigInt(rKey[0] | rKey[1] << 8 | rKey[2] << 16 | rKey[3] << 24), 0x3ffffffn & BigInt(rKey[3] >> 2 | rKey[4] << 6 | rKey[5] << 14 | rKey[6] << 22), 0x3ffffffn & BigInt(rKey[6] >> 4 | rKey[7] << 4 | rKey[8] << 12 | rKey[9] << 20), 0x3ffffffn & BigInt(rKey[9] >> 6 | rKey[10] << 2 | rKey[11] << 10 | rKey[12] << 18), 0x3ffffffn & BigInt(rKey[13] | rKey[14] << 8 | rKey[15] << 16)];
	for (let offset = 0; offset < message.length; offset += 16) {
		const chunk = message.slice(offset, offset + 16),
			paddedChunk = new Uint8Array(17);
		paddedChunk.set(chunk), paddedChunk[chunk.length] = 1, accumulator[0] += BigInt(paddedChunk[0] | paddedChunk[1] << 8 | paddedChunk[2] << 16 | (3 & paddedChunk[3]) << 24), accumulator[1] += BigInt(paddedChunk[3] >> 2 | paddedChunk[4] << 6 | paddedChunk[5] << 14 | (15 & paddedChunk[6]) << 22), accumulator[2] += BigInt(paddedChunk[6] >> 4 | paddedChunk[7] << 4 | paddedChunk[8] << 12 | (63 & paddedChunk[9]) << 20), accumulator[3] += BigInt(paddedChunk[9] >> 6 | paddedChunk[10] << 2 | paddedChunk[11] << 10 | paddedChunk[12] << 18), accumulator[4] += BigInt(paddedChunk[13] | paddedChunk[14] << 8 | paddedChunk[15] << 16 | paddedChunk[16] << 24);
		const product = [0n, 0n, 0n, 0n, 0n];
		for (let accIndex = 0; accIndex < 5; accIndex++)
			for (let rIndex = 0; rIndex < 5; rIndex++) {
				const limbIndex = accIndex + rIndex;
				limbIndex < 5 ? product[limbIndex] += accumulator[accIndex] * rLimbs[rIndex] : product[limbIndex - 5] += accumulator[accIndex] * rLimbs[rIndex] * 5n
			}
		let carry = 0n;
		for (let index = 0; index < 5; index++) product[index] += carry, accumulator[index] = 0x3ffffffn & product[index], carry = product[index] >> 26n;
		accumulator[0] += 5n * carry, carry = accumulator[0] >> 26n, accumulator[0] &= 0x3ffffffn, accumulator[1] += carry
	}
	let tagValue = accumulator[0] | accumulator[1] << 26n | accumulator[2] << 52n | accumulator[3] << 78n | accumulator[4] << 104n;
	tagValue = tagValue + sKey.reduce(((total, byte, index) => total + (BigInt(byte) << BigInt(8 * index))), 0n) & (1n << 128n) - 1n;
	const tag = new Uint8Array(16);
	for (let index = 0; index < 16; index++) tag[index] = Number(tagValue >> BigInt(8 * index) & 0xffn);
	return tag
}

function chacha20Poly1305Encrypt(key, nonce, plaintext, additionalData) {
	const polyKey = chacha20Block(key, 0, nonce).slice(0, 32),
		ciphertext = chacha20Xor(key, nonce, plaintext),
		aadPadding = (16 - additionalData.length % 16) % 16,
		ciphertextPadding = (16 - ciphertext.length % 16) % 16,
		macData = new Uint8Array(additionalData.length + aadPadding + ciphertext.length + ciphertextPadding + 16);
	macData.set(additionalData, 0), macData.set(ciphertext, additionalData.length + aadPadding);
	const lengthView = new DataView(macData.buffer, additionalData.length + aadPadding + ciphertext.length + ciphertextPadding);
	lengthView.setBigUint64(0, BigInt(additionalData.length), !0), lengthView.setBigUint64(8, BigInt(ciphertext.length), !0);
	const tag = poly1305Mac(polyKey, macData);
	return concatBytes(ciphertext, tag)
}

function chacha20Poly1305Decrypt(key, nonce, ciphertext, additionalData) {
	if (ciphertext.length < 16) throw new Error("Ciphertext too short");
	const tag = ciphertext.slice(-16),
		encryptedData = ciphertext.slice(0, -16),
		polyKey = chacha20Block(key, 0, nonce).slice(0, 32),
		aadPadding = (16 - additionalData.length % 16) % 16,
		ciphertextPadding = (16 - encryptedData.length % 16) % 16,
		macData = new Uint8Array(additionalData.length + aadPadding + encryptedData.length + ciphertextPadding + 16);
	macData.set(additionalData, 0), macData.set(encryptedData, additionalData.length + aadPadding);
	const lengthView = new DataView(macData.buffer, additionalData.length + aadPadding + encryptedData.length + ciphertextPadding);
	lengthView.setBigUint64(0, BigInt(additionalData.length), !0), lengthView.setBigUint64(8, BigInt(encryptedData.length), !0);
	const expectedTag = poly1305Mac(polyKey, macData);
	let diff = 0;
	for (let index = 0; index < 16; index++) diff |= tag[index] ^ expectedTag[index];
	if (0 !== diff) throw new Error("ChaCha20-Poly1305 authentication failed");
	return chacha20Xor(key, nonce, encryptedData)
}

const TLS_MAX_PLAINTEXT_FRAGMENT = 16 * 1024;
function buildTlsRecord(contentType, fragment, version = TLS_VERSION_12) {
	const data = toUint8Array(fragment);
	const record = new Uint8Array(5 + data.byteLength);
	record[0] = contentType;
	record[1] = version >> 8 & 255;
	record[2] = version & 255;
	record[3] = data.byteLength >> 8 & 255;
	record[4] = data.byteLength & 255;
	record.set(data, 5);
	return record;
}
function buildHandshakeMessage(handshakeType, body) { return tlsBytes(handshakeType, (length => [length >> 16 & 255, length >> 8 & 255, 255 & length])(body.length), body) }
class TlsRecordParser {
	constructor() { this.buffer = new Uint8Array(0) }
	feed(chunk) {
		const bytes = toUint8Array(chunk);
		this.buffer = this.buffer.length ? concatBytes(this.buffer, bytes) : bytes
	}
	next() {
		if (this.buffer.length < 5) return null;
		const contentType = this.buffer[0],
			version = readUint16(this.buffer, 1),
			length = readUint16(this.buffer, 3);
		if (this.buffer.length < 5 + length) return null;
		const fragment = this.buffer.subarray(5, 5 + length);
		return this.buffer = this.buffer.subarray(5 + length), { type: contentType, version, length, fragment }
	}
}
class TlsHandshakeParser {
	constructor() { this.buffer = new Uint8Array(0) }
	feed(chunk) {
		const bytes = toUint8Array(chunk);
		this.buffer = this.buffer.length ? concatBytes(this.buffer, bytes) : bytes
	}
	next() {
		if (this.buffer.length < 4) return null;
		const handshakeType = this.buffer[0],
			length = readUint24(this.buffer, 1);
		if (this.buffer.length < 4 + length) return null;
		const body = this.buffer.subarray(4, 4 + length),
			raw = this.buffer.subarray(0, 4 + length);
		return this.buffer = this.buffer.subarray(4 + length), { type: handshakeType, length, body, raw }
	}
}

function parseServerHello(body) {
	let offset = 0;
	const legacyVersion = readUint16(body, offset);
	offset += 2;
	const serverRandom = body.slice(offset, offset + 32);
	offset += 32;
	const sessionIdLength = body[offset++],
		sessionId = body.slice(offset, offset + sessionIdLength);
	offset += sessionIdLength;
	const cipherSuite = readUint16(body, offset);
	offset += 2;
	const compression = body[offset++];
	let selectedVersion = legacyVersion,
		keyShare = null,
		alpn = null;
	if (offset < body.length) {
		const extensionsLength = readUint16(body, offset);
		offset += 2;
		const extensionsEnd = offset + extensionsLength;
		for (; offset + 4 <= extensionsEnd;) {
			const extensionType = readUint16(body, offset);
			offset += 2;
			const extensionLength = readUint16(body, offset);
			offset += 2;
			const extensionData = body.slice(offset, offset + extensionLength);
			if (offset += extensionLength, extensionType === EXT_SUPPORTED_VERSIONS && extensionLength >= 2) selectedVersion = readUint16(extensionData, 0);
			else if (extensionType === EXT_KEY_SHARE && extensionLength >= 4) {
				const group = readUint16(extensionData, 0),
					keyLength = readUint16(extensionData, 2);
				keyShare = { group, key: extensionData.slice(4, 4 + keyLength) }
			} else extensionType === EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION && extensionLength >= 3 && (alpn = textDecoder.decode(extensionData.slice(3, 3 + extensionData[2])))
		}
	}
	const helloRetryRequestRandom = new Uint8Array([207, 33, 173, 116, 229, 154, 97, 17, 190, 29, 140, 2, 30, 101, 184, 145, 194, 162, 17, 22, 122, 187, 140, 94, 7, 158, 9, 226, 200, 168, 51, 156]);
	return { version: legacyVersion, serverRandom, sessionId, cipherSuite, compression, selectedVersion, keyShare, alpn, isHRR: constantTimeEqual(serverRandom, helloRetryRequestRandom), isTls13: selectedVersion === TLS_VERSION_13 }
}

function parseServerKeyExchange(body) {
	let offset = 1;
	const namedCurve = readUint16(body, offset);
	offset += 2;
	const keyLength = body[offset++];
	return { namedCurve, serverPublicKey: body.slice(offset, offset + keyLength) }
}

function extractLeafCertificate(body, hasContext = 0) {
	let offset = 0;
	if (hasContext) {
		const contextLength = body[offset++];
		offset += contextLength
	}
	if (offset + 3 > body.length) return null;
	const certificateListLength = readUint24(body, offset);
	if (offset += 3, !certificateListLength || offset + 3 > body.length) return null;
	const certificateLength = readUint24(body, offset);
	return offset += 3, certificateLength ? body.slice(offset, offset + certificateLength) : null
}

function parseEncryptedExtensions(body) {
	const parsed = { alpn: null };
	let offset = 2;
	const extensionsEnd = 2 + readUint16(body, 0);
	for (; offset + 4 <= extensionsEnd;) {
		const extensionType = readUint16(body, offset);
		offset += 2;
		const extensionLength = readUint16(body, offset);
		if (offset += 2, extensionType === EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION && extensionLength >= 3) {
			const protocolLength = body[offset + 2];
			protocolLength > 0 && offset + 3 + protocolLength <= offset + extensionLength && (parsed.alpn = textDecoder.decode(body.slice(offset + 3, offset + 3 + protocolLength)))
		}
		offset += extensionLength
	}
	return parsed
}

function buildClientHello(clientRandom, serverName, keyShares, { tls13: enableTls13 = !0, tls12: enableTls12 = !0, alpn = null, chacha = !0 } = {}) {
	const cipherIds = [];
	enableTls13 && cipherIds.push(4865, 4866, ...(chacha ? [4867] : [])), enableTls12 && cipherIds.push(49199, 49200, 49195, 49196, ...(chacha ? [52392, 52393] : []));
	const cipherBytes = tlsBytes(...cipherIds.flatMap(uint16be)),
		extensions = [tlsBytes(255, 1, 0, 1, 0)];
	if (serverName) {
		const serverNameBytes = textEncoder.encode(serverName),
			serverNameList = tlsBytes(0, uint16be(serverNameBytes.length), serverNameBytes);
		extensions.push(tlsBytes(uint16be(EXT_SERVER_NAME), uint16be(serverNameList.length + 2), uint16be(serverNameList.length), serverNameList))
	}
	extensions.push(tlsBytes(uint16be(EXT_EC_POINT_FORMATS), 0, 2, 1, 0)), extensions.push(tlsBytes(uint16be(EXT_SUPPORTED_GROUPS), 0, 6, 0, 4, 0, 29, 0, 23));
	const signatureBytes = tlsBytes(...SUPPORTED_SIGNATURE_ALGORITHMS.flatMap(uint16be));
	extensions.push(tlsBytes(uint16be(EXT_SIGNATURE_ALGORITHMS), uint16be(signatureBytes.length + 2), uint16be(signatureBytes.length), signatureBytes));
	const protocols = Array.isArray(alpn) ? alpn.filter(Boolean) : alpn ? [alpn] : [];
	if (protocols.length) {
		const alpnBytes = concatBytes(...protocols.map((protocol => { const protocolBytes = textEncoder.encode(protocol); return tlsBytes(protocolBytes.length, protocolBytes) })));
		extensions.push(tlsBytes(uint16be(EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION), uint16be(alpnBytes.length + 2), uint16be(alpnBytes.length), alpnBytes))
	}
	if (enableTls13 && keyShares) {
		let keyShareBytes;
		if (extensions.push(enableTls12 ? tlsBytes(uint16be(EXT_SUPPORTED_VERSIONS), 0, 5, 4, 3, 4, 3, 3) : tlsBytes(uint16be(EXT_SUPPORTED_VERSIONS), 0, 3, 2, 3, 4)), extensions.push(tlsBytes(uint16be(EXT_PSK_KEY_EXCHANGE_MODES), 0, 2, 1, 1)), keyShares?.x25519 && keyShares?.p256) keyShareBytes = concatBytes(tlsBytes(0, 29, uint16be(keyShares.x25519.length), keyShares.x25519), tlsBytes(0, 23, uint16be(keyShares.p256.length), keyShares.p256));
		else if (keyShares?.x25519) keyShareBytes = tlsBytes(0, 29, uint16be(keyShares.x25519.length), keyShares.x25519);
		else if (keyShares?.p256) keyShareBytes = tlsBytes(0, 23, uint16be(keyShares.p256.length), keyShares.p256);
		else {
			if (!(keyShares instanceof Uint8Array)) throw new Error("Invalid keyShares");
			keyShareBytes = tlsBytes(0, 23, uint16be(keyShares.length), keyShares)
		}
		extensions.push(tlsBytes(uint16be(EXT_KEY_SHARE), uint16be(keyShareBytes.length + 2), uint16be(keyShareBytes.length), keyShareBytes))
	}
	const extensionsBytes = concatBytes(...extensions);
	return buildHandshakeMessage(HANDSHAKE_TYPE_CLIENT_HELLO, tlsBytes(uint16be(TLS_VERSION_12), clientRandom, 0, uint16be(cipherBytes.length), cipherBytes, 1, 0, uint16be(extensionsBytes.length), extensionsBytes))
}
const uint64be = sequenceNumber => { const bytes = new Uint8Array(8); return new DataView(bytes.buffer).setBigUint64(0, sequenceNumber, !1), bytes },
	xorSequenceIntoIv = (initializationVector, sequenceNumber) => {
		const nonce = initializationVector.slice(),
			sequenceBytes = uint64be(sequenceNumber);
		for (let index = 0; index < 8; index++) nonce[nonce.length - 8 + index] ^= sequenceBytes[index];
		return nonce
	},
	deriveTrafficKeys = (hash, secret, keyLen, ivLen) => Promise.all([hkdfExpandLabel(hash, secret, "key", EMPTY_BYTES, keyLen), hkdfExpandLabel(hash, secret, "iv", EMPTY_BYTES, ivLen)]);
class TlsClient {
	constructor(socket, options = {}) {
		if (this.socket = socket, this.serverName = options.serverName || "", this.supportTls13 = !1 !== options.tls13, this.supportTls12 = !1 !== options.tls12, !this.supportTls13 && !this.supportTls12) throw new Error("At least one TLS version must be enabled");
		this.alpnProtocols = Array.isArray(options.alpn) ? options.alpn : options.alpn ? [options.alpn] : null, this.allowChacha = options.allowChacha !== false, this.timeout = options.timeout ?? 3e4, this.clientRandom = randomBytes(32), this.serverRandom = null, this.handshakeChunks = [], this.handshakeComplete = !1, this.negotiatedAlpn = null, this.cipherSuite = null, this.cipherConfig = null, this.isTls13 = !1, this.masterSecret = null, this.handshakeSecret = null, this.clientWriteKey = null, this.serverWriteKey = null, this.clientWriteIv = null, this.serverWriteIv = null, this.clientHandshakeKey = null, this.serverHandshakeKey = null, this.clientHandshakeIv = null, this.serverHandshakeIv = null, this.clientAppKey = null, this.serverAppKey = null, this.clientAppIv = null, this.serverAppIv = null, this.clientWriteCryptoKey = null, this.serverWriteCryptoKey = null, this.clientHandshakeCryptoKey = null, this.serverHandshakeCryptoKey = null, this.clientAppCryptoKey = null, this.serverAppCryptoKey = null, this.clientSeqNum = 0n, this.serverSeqNum = 0n, this.recordParser = new TlsRecordParser, this.handshakeParser = new TlsHandshakeParser, this.keyPairs = new Map, this.ecdhKeyPair = null, this.sawCert = !1
	}
	recordHandshake(chunk) { this.handshakeChunks.push(chunk) }
	transcript() { return 1 === this.handshakeChunks.length ? this.handshakeChunks[0] : concatBytes(...this.handshakeChunks) }
	getCipherConfig(cipherSuite) { return CIPHER_SUITES_BY_ID.get(cipherSuite) || null }
	async readChunk(reader) { return this.timeout ? Promise.race([reader.read(), new Promise(((resolve, reject) => setTimeout((() => reject(new Error("TLS read timeout"))), this.timeout)))]) : reader.read() }
	async readRecordsUntil(reader, predicate, closedError) {
		for (; ;) {
			let record;
			for (; record = this.recordParser.next();)
				if (await predicate(record)) return;
			const { value, done } = await this.readChunk(reader);
			if (done) throw new Error(closedError);
			this.recordParser.feed(value)
		}
	}
	async readHandshakeUntil(reader, predicate, closedError) {
		for (let message; message = this.handshakeParser.next();)
			if (await predicate(message)) return;
		return this.readRecordsUntil(reader, (async record => {
			if (record.type === CONTENT_TYPE_ALERT) {
				if (shouldIgnoreTlsAlert(record.fragment)) return;
				throw new Error(`TLS Alert: ${record.fragment[1]}`);
			}
			if (record.type === CONTENT_TYPE_HANDSHAKE) {
				this.handshakeParser.feed(record.fragment);
				for (let message; message = this.handshakeParser.next();)
					if (await predicate(message)) return 1
			}
		}), closedError)
	}
	async acceptCertificate(certificate) { if (!certificate?.length) throw new Error("Empty certificate"); this.sawCert = !0 }
	async handshake() {
		const [p256Share, x25519Share] = await Promise.all([generateKeyShare("P-256"), generateKeyShare("X25519")]);
		this.keyPairs = new Map([[23, p256Share], [29, x25519Share]]), this.ecdhKeyPair = p256Share.keyPair;
		const reader = this.socket.readable.getReader(),
			writer = this.socket.writable.getWriter();
		try {
			const clientHello = buildClientHello(this.clientRandom, this.serverName, { x25519: x25519Share.publicKeyRaw, p256: p256Share.publicKeyRaw }, { tls13: this.supportTls13, tls12: this.supportTls12, alpn: this.alpnProtocols, chacha: this.allowChacha });
			this.recordHandshake(clientHello), await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, clientHello, TLS_VERSION_10));
			const serverHello = await this.receiveServerHello(reader);
			if (serverHello.isHRR) throw new Error("HelloRetryRequest is not supported by TLSClientMini");
			if (serverHello.keyShare?.group && this.keyPairs.has(serverHello.keyShare.group)) {
				const selectedKeyPair = this.keyPairs.get(serverHello.keyShare.group);
				this.ecdhKeyPair = selectedKeyPair.keyPair
			}
			serverHello.isTls13 ? await this.handshakeTls13(reader, writer, serverHello) : await this.handshakeTls12(reader, writer), this.handshakeComplete = !0
		} finally {
			reader.releaseLock(), writer.releaseLock()
		}
	}
	async receiveServerHello(reader) {
		for (; ;) {
			const { value, done } = await this.readChunk(reader);
			if (done) throw new Error("Connection closed waiting for ServerHello");
			let record;
			for (this.recordParser.feed(value); record = this.recordParser.next();) {
				if (record.type === CONTENT_TYPE_ALERT) {
					if (shouldIgnoreTlsAlert(record.fragment)) continue;
					throw new Error(`TLS Alert: level=${record.fragment[0]}, desc=${record.fragment[1]}`);
				}
				if (record.type !== CONTENT_TYPE_HANDSHAKE) continue;
				let message;
				for (this.handshakeParser.feed(record.fragment); message = this.handshakeParser.next();) {
					if (message.type !== HANDSHAKE_TYPE_SERVER_HELLO) continue;
					this.recordHandshake(message.raw);
					const serverHello = parseServerHello(message.body);
					if (this.serverRandom = serverHello.serverRandom, this.cipherSuite = serverHello.cipherSuite, this.cipherConfig = this.getCipherConfig(serverHello.cipherSuite), this.isTls13 = serverHello.isTls13, this.negotiatedAlpn = serverHello.alpn || null, !this.cipherConfig) throw new Error(`Unsupported cipher suite: 0x${serverHello.cipherSuite.toString(16)}`);
					return serverHello
				}
			}
		}
	}
	async handshakeTls12(reader, writer) {
		/** @type {{ namedCurve: number, serverPublicKey: Uint8Array } | null} */
		let serverKeyExchange = null;
		let sawServerHelloDone = !1;
		let clientCertRequested = !1;
		if (await this.readHandshakeUntil(reader, (async message => {
			switch (message.type) {
				case HANDSHAKE_TYPE_CERTIFICATE: {
					this.recordHandshake(message.raw);
					const certificate = extractLeafCertificate(message.body, 1);
					if (!certificate) throw new Error("Missing TLS 1.2 certificate");
					await this.acceptCertificate(certificate);
					break
				}
				case HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE:
					this.recordHandshake(message.raw), serverKeyExchange = parseServerKeyExchange(message.body);
					break;
				case HANDSHAKE_TYPE_SERVER_HELLO_DONE:
					return this.recordHandshake(message.raw), sawServerHelloDone = !0, 1;
				case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
					this.recordHandshake(message.raw), clientCertRequested = !0;
					break;
				default:
					this.recordHandshake(message.raw)
			}
		}), "Connection closed during TLS 1.2 handshake"), !this.sawCert) throw new Error("Missing TLS 1.2 leaf certificate");
		const serverKeyExchangeData = /** @type {{ namedCurve: number, serverPublicKey: Uint8Array } | null} */ (serverKeyExchange);
		if (!serverKeyExchangeData) throw new Error("Missing TLS 1.2 ServerKeyExchange");
		const curveName = GROUPS_BY_ID.get(serverKeyExchangeData.namedCurve);
		if (!curveName) throw new Error(`Unsupported named curve: 0x${serverKeyExchangeData.namedCurve.toString(16)}`);
		const keyShare = this.keyPairs.get(serverKeyExchangeData.namedCurve);
		if (!keyShare) throw new Error(`Missing key pair for curve: 0x${serverKeyExchangeData.namedCurve.toString(16)}`);
		const preMasterSecret = await deriveSharedSecret(keyShare.keyPair.privateKey, serverKeyExchangeData.serverPublicKey, curveName),
			clientKeyExchange = buildHandshakeMessage(HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, tlsBytes(keyShare.publicKeyRaw.length, keyShare.publicKeyRaw));
		if (clientCertRequested) {
			const emptyCertificate = buildHandshakeMessage(HANDSHAKE_TYPE_CERTIFICATE, tlsBytes(0, 0, 0));
			this.recordHandshake(emptyCertificate), await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, emptyCertificate))
		}
		this.recordHandshake(clientKeyExchange);
		const hashName = this.cipherConfig.hash;
		this.masterSecret = await tls12Prf(preMasterSecret, "master secret", concatBytes(this.clientRandom, this.serverRandom), 48, hashName);
		const keyLen = this.cipherConfig.keyLen,
			ivLen = this.cipherConfig.ivLen,
			keyBlock = await tls12Prf(this.masterSecret, "key expansion", concatBytes(this.serverRandom, this.clientRandom), 2 * keyLen + 2 * ivLen, hashName);
		this.clientWriteKey = keyBlock.slice(0, keyLen), this.serverWriteKey = keyBlock.slice(keyLen, 2 * keyLen), this.clientWriteIv = keyBlock.slice(2 * keyLen, 2 * keyLen + ivLen), this.serverWriteIv = keyBlock.slice(2 * keyLen + ivLen, 2 * keyLen + 2 * ivLen);
		if (!this.cipherConfig.chacha) [this.clientWriteCryptoKey, this.serverWriteCryptoKey] = await Promise.all([importAesGcmKey(this.clientWriteKey, ["encrypt"]), importAesGcmKey(this.serverWriteKey, ["decrypt"])]);
		await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, clientKeyExchange)), await writer.write(buildTlsRecord(CONTENT_TYPE_CHANGE_CIPHER_SPEC, tlsBytes(1)));
		const clientVerifyData = await tls12Prf(this.masterSecret, "client finished", await digestBytes(hashName, this.transcript()), 12, hashName),
			finishedMessage = buildHandshakeMessage(HANDSHAKE_TYPE_FINISHED, clientVerifyData);
		this.recordHandshake(finishedMessage), await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, await this.encryptTls12(finishedMessage, CONTENT_TYPE_HANDSHAKE)));
		let sawChangeCipherSpec = !1;
		await this.readRecordsUntil(reader, (async record => {
			if (record.type === CONTENT_TYPE_ALERT) {
				if (shouldIgnoreTlsAlert(record.fragment)) return;
				throw new Error(`TLS Alert: ${record.fragment[1]}`);
			}
			if (record.type === CONTENT_TYPE_CHANGE_CIPHER_SPEC) return void (sawChangeCipherSpec = !0);
			if (record.type !== CONTENT_TYPE_HANDSHAKE || !sawChangeCipherSpec) return;
			const decrypted = await this.decryptTls12(record.fragment, CONTENT_TYPE_HANDSHAKE);
			if (decrypted[0] !== HANDSHAKE_TYPE_FINISHED) return;
			const verifyLength = readUint24(decrypted, 1),
				verifyData = decrypted.slice(4, 4 + verifyLength),
				expectedVerifyData = await tls12Prf(this.masterSecret, "server finished", await digestBytes(hashName, this.transcript()), 12, hashName);
			if (!constantTimeEqual(verifyData, expectedVerifyData)) throw new Error("TLS 1.2 server Finished verify failed");
			return 1
		}), "Connection closed waiting for TLS 1.2 Finished")
	}
	async handshakeTls13(reader, writer, serverHello) {
		const groupName = GROUPS_BY_ID.get(serverHello.keyShare?.group);
		if (!groupName || !serverHello.keyShare?.key?.length) throw new Error("Missing TLS 1.3 key_share");
		const hashName = this.cipherConfig.hash,
			hashLen = hashByteLength(hashName),
			keyLen = this.cipherConfig.keyLen,
			ivLen = this.cipherConfig.ivLen,
			sharedSecret = await deriveSharedSecret(this.ecdhKeyPair.privateKey, serverHello.keyShare.key, groupName),
			earlySecret = await hkdfExtract(hashName, null, new Uint8Array(hashLen)),
			derivedSecret = await hkdfExpandLabel(hashName, earlySecret, "derived", await digestBytes(hashName, EMPTY_BYTES), hashLen);
		this.handshakeSecret = await hkdfExtract(hashName, derivedSecret, sharedSecret);
		const transcriptHash = await digestBytes(hashName, this.transcript()),
			clientHandshakeTrafficSecret = await hkdfExpandLabel(hashName, this.handshakeSecret, "c hs traffic", transcriptHash, hashLen),
			serverHandshakeTrafficSecret = await hkdfExpandLabel(hashName, this.handshakeSecret, "s hs traffic", transcriptHash, hashLen);
		[this.clientHandshakeKey, this.clientHandshakeIv] = await deriveTrafficKeys(hashName, clientHandshakeTrafficSecret, keyLen, ivLen), [this.serverHandshakeKey, this.serverHandshakeIv] = await deriveTrafficKeys(hashName, serverHandshakeTrafficSecret, keyLen, ivLen);
		if (!this.cipherConfig.chacha) [this.clientHandshakeCryptoKey, this.serverHandshakeCryptoKey] = await Promise.all([importAesGcmKey(this.clientHandshakeKey, ["encrypt"]), importAesGcmKey(this.serverHandshakeKey, ["decrypt"])]);
		const serverFinishedKey = await hkdfExpandLabel(hashName, serverHandshakeTrafficSecret, "finished", EMPTY_BYTES, hashLen);
		let serverFinishedReceived = !1;
		let clientCertRequested = !1;
		const handleHandshakeMessage = async message => {
			switch (message.type) {
				case HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: {
					const encryptedExtensions = parseEncryptedExtensions(message.body);
					encryptedExtensions.alpn && (this.negotiatedAlpn = encryptedExtensions.alpn), this.recordHandshake(message.raw);
					break
				}
				case HANDSHAKE_TYPE_CERTIFICATE: {
					const certificate = extractLeafCertificate(message.body);
					if (!certificate) throw new Error("Missing TLS 1.3 certificate");
					await this.acceptCertificate(certificate), this.recordHandshake(message.raw);
					break
				}
				case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
					this.recordHandshake(message.raw), clientCertRequested = !0;
					break;
				case HANDSHAKE_TYPE_CERTIFICATE_VERIFY:
					this.recordHandshake(message.raw);
					break;
				case HANDSHAKE_TYPE_FINISHED: {
					const expectedVerifyData = await hmac(hashName, serverFinishedKey, await digestBytes(hashName, this.transcript()));
					if (!constantTimeEqual(expectedVerifyData, message.body)) throw new Error("TLS 1.3 server Finished verify failed");
					this.recordHandshake(message.raw), serverFinishedReceived = !0;
					break
				}
				default:
					this.recordHandshake(message.raw)
			}
		};
		await this.readRecordsUntil(reader, (async record => {
			if (record.type === CONTENT_TYPE_CHANGE_CIPHER_SPEC || record.type === CONTENT_TYPE_HANDSHAKE) return;
			if (record.type === CONTENT_TYPE_ALERT) {
				if (shouldIgnoreTlsAlert(record.fragment)) return;
				throw new Error(`TLS Alert: ${record.fragment[1]}`);
			}
			if (record.type !== CONTENT_TYPE_APPLICATION_DATA) return;
			const decrypted = await this.decryptTls13Handshake(record.fragment),
				innerType = decrypted[decrypted.length - 1],
				plaintext = decrypted.slice(0, -1);
			if (innerType === CONTENT_TYPE_HANDSHAKE) {
				this.handshakeParser.feed(plaintext);
				for (let message; message = this.handshakeParser.next();)
					if (await handleHandshakeMessage(message), serverFinishedReceived) return 1
			}
		}), "Connection closed during TLS 1.3 handshake");
		const applicationTranscriptHash = await digestBytes(hashName, this.transcript()),
			masterDerivedSecret = await hkdfExpandLabel(hashName, this.handshakeSecret, "derived", await digestBytes(hashName, EMPTY_BYTES), hashLen),
			masterSecret = await hkdfExtract(hashName, masterDerivedSecret, new Uint8Array(hashLen)),
			clientAppTrafficSecret = await hkdfExpandLabel(hashName, masterSecret, "c ap traffic", applicationTranscriptHash, hashLen),
			serverAppTrafficSecret = await hkdfExpandLabel(hashName, masterSecret, "s ap traffic", applicationTranscriptHash, hashLen);
		[this.clientAppKey, this.clientAppIv] = await deriveTrafficKeys(hashName, clientAppTrafficSecret, keyLen, ivLen), [this.serverAppKey, this.serverAppIv] = await deriveTrafficKeys(hashName, serverAppTrafficSecret, keyLen, ivLen);
		if (!this.cipherConfig.chacha) [this.clientAppCryptoKey, this.serverAppCryptoKey] = await Promise.all([importAesGcmKey(this.clientAppKey, ["encrypt"]), importAesGcmKey(this.serverAppKey, ["decrypt"])]);
		let clientFlightHandshake = EMPTY_BYTES;
		if (clientCertRequested) clientFlightHandshake = buildHandshakeMessage(HANDSHAKE_TYPE_CERTIFICATE, tlsBytes(0, 0, 0, 0)), this.recordHandshake(clientFlightHandshake);
		const clientFinishedKey = await hkdfExpandLabel(hashName, clientHandshakeTrafficSecret, "finished", EMPTY_BYTES, hashLen),
			clientFinishedVerifyData = await hmac(hashName, clientFinishedKey, await digestBytes(hashName, this.transcript())),
			clientFinishedMessage = buildHandshakeMessage(HANDSHAKE_TYPE_FINISHED, clientFinishedVerifyData);
		this.recordHandshake(clientFinishedMessage), await writer.write(buildTlsRecord(CONTENT_TYPE_APPLICATION_DATA, await this.encryptTls13Handshake(concatBytes(clientFlightHandshake, clientFinishedMessage, [CONTENT_TYPE_HANDSHAKE])))), this.clientSeqNum = 0n, this.serverSeqNum = 0n
	}
	async encryptTls12(plaintext, contentType) {
		const sequenceNumber = this.clientSeqNum++,
			sequenceBytes = uint64be(sequenceNumber),
			additionalData = concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(plaintext.length));
		if (this.cipherConfig.chacha) {
			const nonce = xorSequenceIntoIv(this.clientWriteIv, sequenceNumber);
			return chacha20Poly1305Encrypt(this.clientWriteKey, nonce, plaintext, additionalData)
		}
		const explicitNonce = randomBytes(8);
		if (!this.clientWriteCryptoKey) this.clientWriteCryptoKey = await importAesGcmKey(this.clientWriteKey, ["encrypt"]);
		return concatBytes(explicitNonce, await aesGcmEncryptWithKey(this.clientWriteCryptoKey, concatBytes(this.clientWriteIv, explicitNonce), plaintext, additionalData))
	}
	async decryptTls12(ciphertext, contentType) {
		const sequenceNumber = this.serverSeqNum++,
			sequenceBytes = uint64be(sequenceNumber);
		if (this.cipherConfig.chacha) {
			const nonce = xorSequenceIntoIv(this.serverWriteIv, sequenceNumber);
			return chacha20Poly1305Decrypt(this.serverWriteKey, nonce, ciphertext, concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(ciphertext.length - 16)))
		}
		const explicitNonce = ciphertext.subarray(0, 8),
			encryptedData = ciphertext.subarray(8);
		if (!this.serverWriteCryptoKey) this.serverWriteCryptoKey = await importAesGcmKey(this.serverWriteKey, ["decrypt"]);
		return aesGcmDecryptWithKey(this.serverWriteCryptoKey, concatBytes(this.serverWriteIv, explicitNonce), encryptedData, concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(encryptedData.length - 16)))
	}
	async encryptTls13Handshake(plaintext) {
		const nonce = xorSequenceIntoIv(this.clientHandshakeIv, this.clientSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(plaintext.length + 16));
		if (this.cipherConfig.chacha) return chacha20Poly1305Encrypt(this.clientHandshakeKey, nonce, plaintext, additionalData);
		if (!this.clientHandshakeCryptoKey) this.clientHandshakeCryptoKey = await importAesGcmKey(this.clientHandshakeKey, ["encrypt"]);
		return aesGcmEncryptWithKey(this.clientHandshakeCryptoKey, nonce, plaintext, additionalData)
	}
	async decryptTls13Handshake(ciphertext) {
		const nonce = xorSequenceIntoIv(this.serverHandshakeIv, this.serverSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(ciphertext.length));
		const decrypted = this.cipherConfig.chacha ? await chacha20Poly1305Decrypt(this.serverHandshakeKey, nonce, ciphertext, additionalData) : await aesGcmDecryptWithKey(this.serverHandshakeCryptoKey || (this.serverHandshakeCryptoKey = await importAesGcmKey(this.serverHandshakeKey, ["decrypt"])), nonce, ciphertext, additionalData);
		let innerTypeIndex = decrypted.length - 1;
		for (; innerTypeIndex >= 0 && !decrypted[innerTypeIndex];) innerTypeIndex--;
		return innerTypeIndex < 0 ? EMPTY_BYTES : decrypted.slice(0, innerTypeIndex + 1)
	}
	async encryptTls13(data) {
		const plaintext = concatBytes(data, [CONTENT_TYPE_APPLICATION_DATA]),
			nonce = xorSequenceIntoIv(this.clientAppIv, this.clientSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(plaintext.length + 16));
		if (this.cipherConfig.chacha) return chacha20Poly1305Encrypt(this.clientAppKey, nonce, plaintext, additionalData);
		if (!this.clientAppCryptoKey) this.clientAppCryptoKey = await importAesGcmKey(this.clientAppKey, ["encrypt"]);
		return aesGcmEncryptWithKey(this.clientAppCryptoKey, nonce, plaintext, additionalData)
	}
	async decryptTls13(ciphertext) {
		const nonce = xorSequenceIntoIv(this.serverAppIv, this.serverSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(ciphertext.length)),
			plaintext = this.cipherConfig.chacha ? await chacha20Poly1305Decrypt(this.serverAppKey, nonce, ciphertext, additionalData) : await aesGcmDecryptWithKey(this.serverAppCryptoKey || (this.serverAppCryptoKey = await importAesGcmKey(this.serverAppKey, ["decrypt"])), nonce, ciphertext, additionalData);
		let innerTypeIndex = plaintext.length - 1;
		for (; innerTypeIndex >= 0 && !plaintext[innerTypeIndex];) innerTypeIndex--;
		if (innerTypeIndex < 0) return {
			data: EMPTY_BYTES,
			type: 0
		};
		return {
			data: plaintext.slice(0, innerTypeIndex),
			type: plaintext[innerTypeIndex]
		}
	}
	async write(data) {
		if (!this.handshakeComplete) throw new Error("Handshake not complete");
		const plaintext = toUint8Array(data);
		if (!plaintext.byteLength) return;
		const writer = this.socket.writable.getWriter();
		try {
			const records = [];
			for (let offset = 0; offset < plaintext.byteLength; offset += TLS_MAX_PLAINTEXT_FRAGMENT) {
				const chunk = plaintext.subarray(offset, Math.min(offset + TLS_MAX_PLAINTEXT_FRAGMENT, plaintext.byteLength));
				const encrypted = this.isTls13 ? await this.encryptTls13(chunk) : await this.encryptTls12(chunk, CONTENT_TYPE_APPLICATION_DATA);
				records.push(buildTlsRecord(CONTENT_TYPE_APPLICATION_DATA, encrypted));
			}
			await writer.write(records.length === 1 ? records[0] : concatBytes(...records))
		} finally {
			writer.releaseLock()
		}
	}
	async read() {
		for (; ;) {
			let record;
			for (; record = this.recordParser.next();) {
				if (record.type === CONTENT_TYPE_ALERT) {
					if (record.fragment[1] === ALERT_CLOSE_NOTIFY) return null;
					throw new Error(`TLS Alert: ${record.fragment[1]}`)
				}
				if (record.type !== CONTENT_TYPE_APPLICATION_DATA) continue;
				if (!this.isTls13) return this.decryptTls12(record.fragment, CONTENT_TYPE_APPLICATION_DATA);
				const { data, type } = await this.decryptTls13(record.fragment);
				if (type === CONTENT_TYPE_APPLICATION_DATA) return data;
				if (type === CONTENT_TYPE_ALERT) {
					if (data[1] === ALERT_CLOSE_NOTIFY) return null;
					throw new Error(`TLS Alert: ${data[1]}`)
				}
				if (type !== CONTENT_TYPE_HANDSHAKE) continue;
				let message;
				for (this.handshakeParser.feed(data); message = this.handshakeParser.next();)
					if (message.type !== HANDSHAKE_TYPE_NEW_SESSION_TICKET && message.type === HANDSHAKE_TYPE_KEY_UPDATE) throw new Error("TLS 1.3 KeyUpdate is not supported by TLSClientMini")
			}
			const reader = this.socket.readable.getReader();
			try {
				const { value, done } = await this.readChunk(reader);
				if (done) return null;
				this.recordParser.feed(value)
			} finally {
				reader.releaseLock()
			}
		}
	}
	close() { this.socket.close() }
}

function stripIPv6Brackets(hostname = '') {
	const host = String(hostname || '').trim();
	return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

function isIPHostname(hostname = '') {
	const host = stripIPv6Brackets(hostname);
	const ipv4Regex = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
	if (ipv4Regex.test(host)) return true;
	if (!host.includes(':')) return false;
	try {
		new URL(`http://[${host}]/`);
		return true;
	} catch (e) {
		return false;
	}
}

//////////////////////////////////////////////////TURN 链式代理（STUN/TURN 协商）///////////////////////////////////////////////
const CONNECT_TIMEOUT_MS = 9999;
const TURN_STUN_MAGIC_COOKIE = new Uint8Array([0x21, 0x12, 0xa4, 0x42]);
const TURN_STUN_TYPE = {
	ALLOCATE_REQUEST: 0x0003, ALLOCATE_SUCCESS: 0x0103, ALLOCATE_ERROR: 0x0113,
	CREATE_PERMISSION_REQUEST: 0x0008, CREATE_PERMISSION_SUCCESS: 0x0108,
	CONNECT_REQUEST: 0x000a, CONNECT_SUCCESS: 0x010a,
	CONNECTION_BIND_REQUEST: 0x000b, CONNECTION_BIND_SUCCESS: 0x010b
};
const TURN_STUN_ATTR = {
	USERNAME: 0x0006, MESSAGE_INTEGRITY: 0x0008, ERROR_CODE: 0x0009,
	XOR_PEER_ADDRESS: 0x0012, REALM: 0x0014, NONCE: 0x0015,
	REQUESTED_TRANSPORT: 0x0019, CONNECTION_ID: 0x002a
};

async function withTimeout(promise, timeoutMs, message) {
	let timer;
	try {
		return await Promise.race([
			promise,
			new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message)), timeoutMs) })
		]);
	} finally {
		clearTimeout(timer);
	}
}

function isIPv4(value) {
	const parts = String(value || '').split('.');
	return parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function turnStunPadding(length) {
	return -length & 3;
}

function createTurnStunAttribute(type, value) {
	const body = toUint8Array(value);
	const attribute = new Uint8Array(4 + body.byteLength + turnStunPadding(body.byteLength));
	const view = new DataView(attribute.buffer);
	view.setUint16(0, type);
	view.setUint16(2, body.byteLength);
	attribute.set(body, 4);
	return attribute;
}

function createTurnStunMessage(type, transactionId, attributes) {
	const body = concatByteChunks(...attributes);
	const header = new Uint8Array(20);
	const view = new DataView(header.buffer);
	view.setUint16(0, type);
	view.setUint16(2, body.byteLength);
	header.set(TURN_STUN_MAGIC_COOKIE, 4);
	header.set(transactionId, 8);
	return concatByteChunks(header, body);
}

function parseTurnErrorCode(data) {
	return data?.byteLength >= 4 ? (data[2] & 7) * 100 + data[3] : 0;
}

function randomTurnTransactionId() {
	return crypto.getRandomValues(new Uint8Array(12));
}

async function addTurnMessageIntegrity(message, key) {
	const signedMessage = new Uint8Array(message);
	const view = new DataView(signedMessage.buffer);
	view.setUint16(2, view.getUint16(2) + 24);
	const hmacKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
	const signature = await crypto.subtle.sign('HMAC', hmacKey, signedMessage);
	return concatByteChunks(signedMessage, createTurnStunAttribute(TURN_STUN_ATTR.MESSAGE_INTEGRITY, new Uint8Array(signature)));
}

async function readTurnStunMessage(reader, bufferedData = null, timeoutMessage = 'TURN response timed out') {
	let buffer = effectiveByteLength(bufferedData) ? toUint8Array(bufferedData) : new Uint8Array(0);
	const pull = async () => {
		const { done, value } = await withTimeout(reader.read(), CONNECT_TIMEOUT_MS, timeoutMessage);
		if (done) throw new Error('TURN server closed connection');
		if (value?.byteLength) buffer = concatByteChunks(buffer, value);
	};
	while (buffer.byteLength < 20) await pull();

	const messageLength = 20 + ((buffer[2] << 8) | buffer[3]);
	if (messageLength > 65555) throw new Error('TURN response is too large');
	while (buffer.byteLength < messageLength) await pull();
	const messageBuffer = buffer.subarray(0, messageLength);
	if (TURN_STUN_MAGIC_COOKIE.some((value, index) => messageBuffer[4 + index] !== value)) throw new Error('Invalid TURN/STUN response');

	const view = new DataView(messageBuffer.buffer, messageBuffer.byteOffset, messageBuffer.byteLength);
	const attributes = {};
	for (let offset = 20; offset + 4 <= messageLength;) {
		const type = view.getUint16(offset);
		const length = view.getUint16(offset + 2);
		if (offset + 4 + length > messageBuffer.byteLength) break;
		attributes[type] = messageBuffer.slice(offset + 4, offset + 4 + length);
		offset += 4 + length + turnStunPadding(length);
	}
	return {
		message: { type: view.getUint16(0), attributes },
		extraData: buffer.byteLength > messageLength ? buffer.subarray(messageLength) : null
	};
}

async function writeTurnBytes(writer, bytes, timeoutMessage) {
	await withTimeout(writer.write(bytes), CONNECT_TIMEOUT_MS, timeoutMessage);
}

async function turnConnect(proxy, targetHost, targetPort, tcpConnect) {
	proxy = { ...proxy, username: proxy.username ?? null, password: proxy.password ?? null };
	const resolvedTargetHost = stripIPv6Brackets(targetHost);
	/** @type {string | null} */
	let targetIp = isIPv4(resolvedTargetHost) ? resolvedTargetHost : null;
	if (!targetIp) {
		const records = await dohQuery(resolvedTargetHost, 'A');
		const recordData = records.find(item => item.type === 1 && isIPv4(item.data))?.data;
		targetIp = typeof recordData === 'string' ? recordData : null;
	}
	if (!targetIp) throw new Error(`Could not resolve ${targetHost} to an IPv4 address for TURN CONNECT`);

	const turnHost = stripIPv6Brackets(proxy.hostname);
	let controlSocket = null, dataSocket = null, controlWriter = null, controlReader = null, dataWriter = null, dataReader = null, dataReaderReleased = false;
	const close = () => {
		try { controlSocket?.close?.() } catch (e) { }
		try { dataSocket?.close?.() } catch (e) { }
	};
	const releaseDataReader = () => {
		if (dataReaderReleased) return;
		dataReaderReleased = true;
		try { dataReader?.releaseLock?.() } catch (e) { }
	};

	try {
		controlSocket = tcpConnect({ hostname: turnHost, port: proxy.port });
		await withTimeout(controlSocket.opened, CONNECT_TIMEOUT_MS, 'TURN server connection timed out');
		controlWriter = controlSocket.writable.getWriter();
		controlReader = controlSocket.readable.getReader();

		const xorPeerAddress = new Uint8Array(8);
		xorPeerAddress[1] = 1;
		new DataView(xorPeerAddress.buffer).setUint16(2, targetPort ^ 0x2112);
		targetIp.split('.').forEach((value, index) => {
			xorPeerAddress[4 + index] = Number(value) ^ TURN_STUN_MAGIC_COOKIE[index];
		});
		const peerAddress = createTurnStunAttribute(TURN_STUN_ATTR.XOR_PEER_ADDRESS, xorPeerAddress);
		const requestedTransport = new Uint8Array([6, 0, 0, 0]);

		await writeTurnBytes(controlWriter, createTurnStunMessage(
			TURN_STUN_TYPE.ALLOCATE_REQUEST,
			randomTurnTransactionId(),
			[createTurnStunAttribute(TURN_STUN_ATTR.REQUESTED_TRANSPORT, requestedTransport)]
		), 'TURN Allocate request timed out');

		let turnResponse = await readTurnStunMessage(controlReader, null, 'TURN Allocate response timed out');
		let message = turnResponse.message;
		let bufferedData = turnResponse.extraData;
		let integrityKey = null;
		let authAttributes = [];
		const sign = messageToSign => integrityKey ? addTurnMessageIntegrity(messageToSign, integrityKey) : Promise.resolve(messageToSign);

		if (
			message.type === TURN_STUN_TYPE.ALLOCATE_ERROR
			&& proxy.username !== null
			&& proxy.password !== null
			&& parseTurnErrorCode(message.attributes[TURN_STUN_ATTR.ERROR_CODE]) === 401
		) {
			const realmBytes = message.attributes[TURN_STUN_ATTR.REALM];
			const nonce = message.attributes[TURN_STUN_ATTR.NONCE];
			if (!realmBytes || !nonce?.byteLength) throw new Error('TURN authentication challenge is missing realm or nonce');

			const realm = textDecoder.decode(realmBytes);
			integrityKey = new Uint8Array(await crypto.subtle.digest('MD5', textEncoder.encode(`${proxy.username}:${realm}:${proxy.password}`)));
			authAttributes = [
				createTurnStunAttribute(TURN_STUN_ATTR.USERNAME, textEncoder.encode(proxy.username)),
				createTurnStunAttribute(TURN_STUN_ATTR.REALM, textEncoder.encode(realm)),
				createTurnStunAttribute(TURN_STUN_ATTR.NONCE, nonce)
			];

			const allocateRequest = await addTurnMessageIntegrity(createTurnStunMessage(
				TURN_STUN_TYPE.ALLOCATE_REQUEST,
				randomTurnTransactionId(),
				[
					createTurnStunAttribute(TURN_STUN_ATTR.REQUESTED_TRANSPORT, requestedTransport),
					...authAttributes
				]
			), integrityKey);
			const pipelinedMessages = await Promise.all([
				sign(createTurnStunMessage(TURN_STUN_TYPE.CREATE_PERMISSION_REQUEST, randomTurnTransactionId(), [peerAddress, ...authAttributes])),
				sign(createTurnStunMessage(TURN_STUN_TYPE.CONNECT_REQUEST, randomTurnTransactionId(), [peerAddress, ...authAttributes]))
			]);
			await writeTurnBytes(controlWriter, concatByteChunks(allocateRequest, ...pipelinedMessages), 'TURN authenticated Allocate request timed out');
			turnResponse = await readTurnStunMessage(controlReader, bufferedData, 'TURN authenticated Allocate response timed out');
			message = turnResponse.message;
			bufferedData = turnResponse.extraData;
		} else if (message.type === TURN_STUN_TYPE.ALLOCATE_SUCCESS) {
			const pipelinedMessages = await Promise.all([
				sign(createTurnStunMessage(TURN_STUN_TYPE.CREATE_PERMISSION_REQUEST, randomTurnTransactionId(), [peerAddress, ...authAttributes])),
				sign(createTurnStunMessage(TURN_STUN_TYPE.CONNECT_REQUEST, randomTurnTransactionId(), [peerAddress, ...authAttributes]))
			]);
			if (pipelinedMessages.length) await writeTurnBytes(controlWriter, concatByteChunks(...pipelinedMessages), 'TURN pipelined request timed out');
		}

		if (message.type !== TURN_STUN_TYPE.ALLOCATE_SUCCESS) {
			const errorCode = parseTurnErrorCode(message.attributes[TURN_STUN_ATTR.ERROR_CODE]);
			throw new Error(errorCode ? `TURN Allocate failed with ${errorCode}` : 'TURN Allocate failed');
		}

		dataSocket = tcpConnect({ hostname: turnHost, port: proxy.port });
		turnResponse = await readTurnStunMessage(controlReader, bufferedData, 'TURN CreatePermission response timed out');
		message = turnResponse.message;
		bufferedData = turnResponse.extraData;
		if (message.type !== TURN_STUN_TYPE.CREATE_PERMISSION_SUCCESS) throw new Error('TURN CreatePermission failed');

		turnResponse = await readTurnStunMessage(controlReader, bufferedData, 'TURN CONNECT response timed out');
		message = turnResponse.message;
		bufferedData = turnResponse.extraData;
		if (message.type !== TURN_STUN_TYPE.CONNECT_SUCCESS || !message.attributes[TURN_STUN_ATTR.CONNECTION_ID]) throw new Error('TURN CONNECT failed');

		await withTimeout(dataSocket.opened, CONNECT_TIMEOUT_MS, 'TURN data connection timed out');
		dataWriter = dataSocket.writable.getWriter();
		dataReader = dataSocket.readable.getReader();
		await writeTurnBytes(dataWriter, await sign(createTurnStunMessage(
			TURN_STUN_TYPE.CONNECTION_BIND_REQUEST,
			randomTurnTransactionId(),
			[
				createTurnStunAttribute(TURN_STUN_ATTR.CONNECTION_ID, message.attributes[TURN_STUN_ATTR.CONNECTION_ID]),
				...authAttributes
			]
		)), 'TURN ConnectionBind request timed out');

		turnResponse = await readTurnStunMessage(dataReader, null, 'TURN ConnectionBind response timed out');
		message = turnResponse.message;
		const extraPayload = turnResponse.extraData;
		if (message.type !== TURN_STUN_TYPE.CONNECTION_BIND_SUCCESS) throw new Error('TURN ConnectionBind failed');

		controlWriter.releaseLock();
		controlWriter = null;
		controlReader.releaseLock();
		controlReader = null;
		dataWriter.releaseLock();
		dataWriter = null;

		const readable = new ReadableStream({
			start(controller) {
				if (extraPayload?.byteLength) controller.enqueue(extraPayload);
			},
			pull(controller) {
				return dataReader.read().then(({ done, value }) => {
					if (done) {
						releaseDataReader();
						controller.close();
					} else if (value?.byteLength) controller.enqueue(new Uint8Array(value));
				});
			},
			cancel() {
				try { dataReader?.cancel?.() } catch (e) { }
				releaseDataReader();
				close();
			}
		});

		return { readable, writable: dataSocket.writable, closed: dataSocket.closed, close };
	} catch (error) {
		try { controlWriter?.releaseLock?.() } catch (e) { }
		try { controlReader?.releaseLock?.() } catch (e) { }
		try { dataWriter?.releaseLock?.() } catch (e) { }
		releaseDataReader();
		close();
		throw error;
	}
}
//////////////////////////////////////////////////SSTP 链式代理（PPP over SSTP）///////////////////////////////////////////////
const SSTP_TCP_MSS = 1400;
const SSTP_EMPTY_BYTES = new Uint8Array(0);

function readSstpUint16(bytes, offset = 0) {
	return (bytes[offset] << 8) | bytes[offset + 1];
}

function readSstpUint32(bytes, offset = 0) {
	return ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
}

function randomSstpUint16() {
	return readSstpUint16(crypto.getRandomValues(new Uint8Array(2)));
}

function internetChecksum(bytes, offset, length) {
	let sum = 0;
	for (let index = offset; index < offset + length - 1; index += 2) sum += readSstpUint16(bytes, index);
	if (length & 1) sum += bytes[offset + length - 1] << 8;
	while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
	return (~sum) & 0xffff;
}

async function sstpConnect(proxy, targetHost, targetPort, tcpConnect) {
	proxy = { ...proxy, username: proxy.username ?? null, password: proxy.password ?? null };
	let bufferedBytes = SSTP_EMPTY_BYTES, pppIdentifier = 1, socket = null, reader = null, writer = null;
	let closedSettled = false, resolveClosed, rejectClosed;
	const closed = new Promise((resolve, reject) => {
		resolveClosed = resolve;
		rejectClosed = reject;
	});
	const settleClosed = (settle, value) => {
		if (closedSettled) return;
		closedSettled = true;
		settle(value);
	};
	const close = () => {
		try { reader?.cancel?.().catch?.(() => { }) } catch (e) { }
		try { reader?.releaseLock?.() } catch (e) { }
		try { writer?.close?.().catch?.(() => { }) } catch (e) { }
		try { writer?.releaseLock?.() } catch (e) { }
		try { socket?.close?.() } catch (e) { }
		settleClosed(resolveClosed);
	};

	const readSocketChunk = async () => {
		const { value, done } = await reader.read();
		if (done || !value) throw new Error('SSTP socket closed');
		return toUint8Array(value);
	};
	const readBytes = async length => {
		while (bufferedBytes.byteLength < length) {
			const chunk = await readSocketChunk();
			bufferedBytes = bufferedBytes.byteLength ? concatByteChunks(bufferedBytes, chunk) : chunk;
		}
		const result = bufferedBytes.subarray(0, length);
		bufferedBytes = bufferedBytes.subarray(length);
		return result;
	};
	const readHttpLine = async () => {
		for (; ;) {
			const lineEnd = bufferedBytes.indexOf(10);
			if (lineEnd >= 0) {
				const line = textDecoder.decode(bufferedBytes.subarray(0, lineEnd));
				bufferedBytes = bufferedBytes.subarray(lineEnd + 1);
				return line.replace(/\r$/, '');
			}
			const chunk = await readSocketChunk();
			bufferedBytes = bufferedBytes.byteLength ? concatByteChunks(bufferedBytes, chunk) : chunk;
		}
	};
	const readPacket = async (timeoutMs = CONNECT_TIMEOUT_MS) => {
		const header = await withTimeout(readBytes(4), timeoutMs, 'SSTP read timeout');
		const length = readSstpUint16(header, 2) & 0x0fff;
		if (length < 4) throw new Error('Invalid SSTP packet length');
		return {
			isControl: (header[1] & 1) !== 0,
			body: length > 4 ? await withTimeout(readBytes(length - 4), timeoutMs, 'SSTP packet body read timeout') : SSTP_EMPTY_BYTES
		};
	};
	const buildSstpDataPacket = pppFrame => {
		const packetLength = 6 + pppFrame.byteLength;
		const packet = new Uint8Array(packetLength);
		packet.set([0x10, 0x00, ((packetLength >> 8) & 0x0f) | 0x80, packetLength & 0xff, 0xff, 0x03]);
		packet.set(pppFrame, 6);
		return packet;
	};
	const buildPppConfigurePacket = (protocol, code, id, options = []) => {
		const optionsLength = options.reduce((size, option) => size + 2 + option.data.byteLength, 0);
		const frame = new Uint8Array(6 + optionsLength);
		const view = new DataView(frame.buffer);
		view.setUint16(0, protocol);
		frame[2] = code;
		frame[3] = id;
		view.setUint16(4, 4 + optionsLength);
		options.reduce((offset, option) => {
			frame[offset] = option.type;
			frame[offset + 1] = 2 + option.data.byteLength;
			frame.set(option.data, offset + 2);
			return offset + 2 + option.data.byteLength;
		}, 6);
		return frame;
	};
	const parsePPPFrame = data => {
		const offset = data.byteLength >= 2 && data[0] === 0xff && data[1] === 0x03 ? 2 : 0;
		if (data.byteLength - offset < 4) return null;
		const protocol = readSstpUint16(data, offset);
		if (protocol === 0x0021) return { protocol, ipPacket: data.subarray(offset + 2) };
		if (data.byteLength - offset < 6) return null;
		return { protocol, code: data[offset + 2], id: data[offset + 3], payload: data.subarray(offset + 6), rawPacket: data.subarray(offset) };
	};
	const parsePppOptions = data => {
		const options = [];
		for (let offset = 0; offset + 2 <= data.byteLength;) {
			const type = data[offset];
			const length = data[offset + 1];
			if (length < 2 || offset + length > data.byteLength) break;
			options.push({ type, data: data.subarray(offset + 2, offset + length) });
			offset += length;
		}
		return options;
	};

	try {
		const serverHost = stripIPv6Brackets(proxy.hostname);
		const serverPort = proxy.port;
		socket = tcpConnect({ hostname: serverHost, port: serverPort }, { secureTransport: 'on', allowHalfOpen: false });
		await withTimeout(socket.opened, CONNECT_TIMEOUT_MS, 'SSTP server connection timed out');
		reader = socket.readable.getReader();
		writer = socket.writable.getWriter();

		const displayHost = serverHost.includes(':') ? `[${serverHost}]` : serverHost;
		const httpRequest = textEncoder.encode(
			`SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n`
			+ `Host: ${Number(serverPort) === 443 ? displayHost : `${displayHost}:${serverPort}`}\r\n`
			+ 'Content-Length: 18446744073709551615\r\n'
			+ `SSTPCORRELATIONID: {${crypto.randomUUID()}}\r\n\r\n`
		);
		const encapsulatedProtocol = new Uint8Array(2);
		new DataView(encapsulatedProtocol.buffer).setUint16(0, 1);
		const maximumReceiveUnit = new Uint8Array(2);
		new DataView(maximumReceiveUnit.buffer).setUint16(0, 1500);
		const sstpConnectRequest = new Uint8Array(12 + encapsulatedProtocol.byteLength);
		const sstpConnectView = new DataView(sstpConnectRequest.buffer);
		sstpConnectRequest[0] = 0x10;
		sstpConnectRequest[1] = 0x01;
		sstpConnectView.setUint16(2, sstpConnectRequest.byteLength | 0x8000);
		sstpConnectView.setUint16(4, 0x0001);
		sstpConnectView.setUint16(6, 1);
		sstpConnectRequest[9] = 1;
		sstpConnectView.setUint16(10, 4 + encapsulatedProtocol.byteLength);
		sstpConnectRequest.set(encapsulatedProtocol, 12);

		await withTimeout(writer.write(concatByteChunks(
			httpRequest,
			sstpConnectRequest,
			buildSstpDataPacket(buildPppConfigurePacket(0xc021, 1, pppIdentifier++, [
				{ type: 1, data: maximumReceiveUnit }
			]))
		)), CONNECT_TIMEOUT_MS, 'SSTP HTTP handshake request timed out');

		const statusLine = await withTimeout(readHttpLine(), CONNECT_TIMEOUT_MS, 'SSTP HTTP handshake timed out');
		for (; ;) {
			const line = await withTimeout(readHttpLine(), CONNECT_TIMEOUT_MS, 'SSTP HTTP header read timed out');
			if (line === '') break;
		}
		if (!/HTTP\/\d(?:\.\d)?\s+2\d\d/i.test(statusLine)) throw new Error(`SSTP HTTP handshake failed: ${statusLine || 'invalid status'}`);

		let localLcpAcked = false, peerLcpAcked = false, papRequired = false, papSent = false, papDone = false, ipcpStarted = false, ipcpFinished = false, sourceIp = null;
		const sendPapIfReady = async () => {
			if (!localLcpAcked || !peerLcpAcked || !papRequired || papSent) return;
			if (proxy.username === null || proxy.password === null) throw new Error('SSTP server requires PAP authentication');
			const username = textEncoder.encode(proxy.username);
			const password = textEncoder.encode(proxy.password);
			if (username.byteLength > 255 || password.byteLength > 255) throw new Error('SSTP username/password is too long');
			const papLength = 6 + username.byteLength + password.byteLength;
			const frame = new Uint8Array(2 + papLength);
			const view = new DataView(frame.buffer);
			view.setUint16(0, 0xc023);
			frame[2] = 1;
			frame[3] = pppIdentifier++;
			view.setUint16(4, papLength);
			frame[6] = username.byteLength;
			frame.set(username, 7);
			frame[7 + username.byteLength] = password.byteLength;
			frame.set(password, 8 + username.byteLength);
			await withTimeout(writer.write(buildSstpDataPacket(frame)), CONNECT_TIMEOUT_MS, 'SSTP PAP authentication request timed out');
			papSent = true;
		};
		const startIpcpIfReady = async () => {
			if (!localLcpAcked || !peerLcpAcked || ipcpStarted || (papRequired && !papDone)) return;
			await withTimeout(writer.write(buildSstpDataPacket(buildPppConfigurePacket(0x8021, 1, pppIdentifier++, [
				{ type: 3, data: new Uint8Array(4) }
			]))), CONNECT_TIMEOUT_MS, 'SSTP IPCP request timed out');
			ipcpStarted = true;
		};

		for (let round = 0; round < 50 && !ipcpFinished; round++) {
			const packet = await readPacket(CONNECT_TIMEOUT_MS);
			if (packet.isControl) continue;
			const ppp = parsePPPFrame(packet.body);
			if (!ppp) continue;

			if (ppp.protocol === 0xc021) {
				if (ppp.code === 1) {
					const authOption = parsePppOptions(ppp.payload).find(option => option.type === 3);
					if (authOption?.data?.byteLength >= 2) {
						const authProtocol = readSstpUint16(authOption.data);
						if (authProtocol !== 0xc023) throw new Error(`SSTP unsupported PPP authentication protocol: 0x${authProtocol.toString(16)}`);
						papRequired = true;
					}
					const ack = new Uint8Array(ppp.rawPacket);
					ack[2] = 2;
					await withTimeout(writer.write(buildSstpDataPacket(ack)), CONNECT_TIMEOUT_MS, 'SSTP LCP Configure-Ack timed out');
					peerLcpAcked = true;
					await sendPapIfReady();
					await startIpcpIfReady();
				} else if (ppp.code === 2) {
					localLcpAcked = true;
					await sendPapIfReady();
					await startIpcpIfReady();
				}
				continue;
			}

			if (ppp.protocol === 0xc023) {
				if (ppp.code === 2) {
					papDone = true;
					await startIpcpIfReady();
				} else if (ppp.code === 3) throw new Error('SSTP PAP authentication failed');
				continue;
			}

			if (ppp.protocol === 0x8021) {
				if (ppp.code === 1) {
					const ack = new Uint8Array(ppp.rawPacket);
					ack[2] = 2;
					await withTimeout(writer.write(buildSstpDataPacket(ack)), CONNECT_TIMEOUT_MS, 'SSTP IPCP Configure-Ack timed out');
					await startIpcpIfReady();
				} else if (ppp.code === 3) {
					const addressOption = parsePppOptions(ppp.payload).find(option => option.type === 3);
					if (addressOption?.data?.byteLength === 4) {
						sourceIp = [...addressOption.data].join('.');
						await withTimeout(writer.write(buildSstpDataPacket(buildPppConfigurePacket(0x8021, 1, pppIdentifier++, [
							{ type: 3, data: addressOption.data }
						]))), CONNECT_TIMEOUT_MS, 'SSTP IPCP address request timed out');
						ipcpStarted = true;
					}
				} else if (ppp.code === 2) {
					const addressOption = parsePppOptions(ppp.payload).find(option => option.type === 3);
					if (addressOption?.data?.byteLength === 4) sourceIp = [...addressOption.data].join('.');
					ipcpFinished = true;
				}
			}
		}
		if (!sourceIp) throw new Error('SSTP did not assign an IPv4 address');

		const target = stripIPv6Brackets(targetHost);
		/** @type {string | null} */
		let targetIp = isIPv4(target) ? target : null;
		if (!targetIp) {
			const records = await dohQuery(target, 'A');
			const recordData = records.find(item => item.type === 1 && isIPv4(item.data))?.data;
			targetIp = typeof recordData === 'string' ? recordData : null;
		}
		if (!targetIp) throw new Error(`Could not resolve ${targetHost} to an IPv4 address for SSTP`);

		const sourcePort = 10000 + (randomSstpUint16() % 50000);
		const sourceAddress = new Uint8Array(String(sourceIp || '').split('.').map(Number));
		const destinationAddress = new Uint8Array(String(targetIp || '').split('.').map(Number));
		let sequenceNumber = readSstpUint32(crypto.getRandomValues(new Uint8Array(4)));
		let acknowledgementNumber = 0;
		const ipHeaderTemplate = new Uint8Array(20);
		ipHeaderTemplate.set([0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 64, 6]);
		ipHeaderTemplate.set(sourceAddress, 12);
		ipHeaderTemplate.set(destinationAddress, 16);
		const tcpPseudoHeader = new Uint8Array(1432);
		tcpPseudoHeader.set(sourceAddress);
		tcpPseudoHeader.set(destinationAddress, 4);
		tcpPseudoHeader[9] = 6;
		const buildTcpFrame = (flags, payload = SSTP_EMPTY_BYTES) => {
			const bytes = toUint8Array(payload);
			const payloadLength = bytes.byteLength;
			const tcpLength = 20 + payloadLength;
			const ipLength = 20 + tcpLength;
			const sstpLength = 8 + ipLength;
			const frame = new Uint8Array(sstpLength);
			const view = new DataView(frame.buffer);
			frame.set([0x10, 0x00, ((sstpLength >> 8) & 0x0f) | 0x80, sstpLength & 0xff, 0xff, 0x03, 0x00, 0x21]);
			frame.set(ipHeaderTemplate, 8);
			view.setUint16(10, ipLength);
			view.setUint16(12, randomSstpUint16());
			view.setUint16(18, internetChecksum(frame, 8, 20));
			view.setUint16(28, sourcePort);
			view.setUint16(30, targetPort);
			view.setUint32(32, sequenceNumber);
			view.setUint32(36, acknowledgementNumber);
			frame[40] = 0x50;
			frame[41] = flags;
			view.setUint16(42, 65535);
			if (payloadLength) frame.set(bytes, 48);
			tcpPseudoHeader[10] = tcpLength >> 8;
			tcpPseudoHeader[11] = tcpLength & 0xff;
			tcpPseudoHeader.set(frame.subarray(28, 28 + tcpLength), 12);
			view.setUint16(44, internetChecksum(tcpPseudoHeader, 0, 12 + tcpLength));
			return frame;
		};
		const matchIncomingIpPacket = ipPacket => {
			if (ipPacket.byteLength < 40 || ipPacket[9] !== 6) return null;
			const ipHeaderLength = (ipPacket[0] & 0x0f) * 4;
			if (ipPacket.byteLength < ipHeaderLength + 20) return null;
			if (readSstpUint16(ipPacket, ipHeaderLength) !== targetPort) return null;
			if (readSstpUint16(ipPacket, ipHeaderLength + 2) !== sourcePort) return null;
			return {
				flags: ipPacket[ipHeaderLength + 13],
				sequence: readSstpUint32(ipPacket, ipHeaderLength + 4),
				payloadOffset: ipHeaderLength + ((ipPacket[ipHeaderLength + 12] >> 4) & 0x0f) * 4
			};
		};

		await withTimeout(writer.write(buildTcpFrame(0x02)), CONNECT_TIMEOUT_MS, 'SSTP TCP SYN write timed out');
		sequenceNumber = (sequenceNumber + 1) >>> 0;
		let tcpReady = false;
		for (let attempt = 0; attempt < 30; attempt++) {
			const packet = await readPacket(CONNECT_TIMEOUT_MS);
			if (packet.isControl) continue;
			const ppp = parsePPPFrame(packet.body);
			if (!ppp || ppp.protocol !== 0x0021) continue;
			const tcp = matchIncomingIpPacket(ppp.ipPacket);
			if (!tcp || (tcp.flags & 0x12) !== 0x12) continue;
			acknowledgementNumber = (tcp.sequence + 1) >>> 0;
			await withTimeout(writer.write(buildTcpFrame(0x10)), CONNECT_TIMEOUT_MS, 'SSTP TCP ACK write timed out');
			tcpReady = true;
			break;
		}
		if (!tcpReady) throw new Error('TCP handshake through SSTP timed out');

		/** @type {ReadableStreamDefaultController<Uint8Array> | null} */
		let streamController = null;
		const readable = new ReadableStream({
			start(controller) {
				streamController = controller;
			},
			cancel() {
				close();
			}
		});

		(async () => {
			try {
				let pendingChunks = [], pendingLength = 0;
				const flush = () => {
					if (!pendingLength) return;
					if (!streamController) throw new Error('SSTP readable stream is not ready');
					streamController.enqueue(pendingChunks.length === 1 ? pendingChunks[0] : concatByteChunks(...pendingChunks));
					pendingChunks = [];
					pendingLength = 0;
					writer.write(buildTcpFrame(0x10)).catch(() => { });
				};

				for (; ;) {
					const packet = await readPacket(60000);
					if (packet.isControl) continue;
					const ppp = parsePPPFrame(packet.body);
					if (!ppp || ppp.protocol !== 0x0021) continue;
					const incoming = matchIncomingIpPacket(ppp.ipPacket);
					if (!incoming) continue;

					if (incoming.payloadOffset < ppp.ipPacket.byteLength) {
						const payload = ppp.ipPacket.subarray(incoming.payloadOffset);
						if (payload.byteLength) {
							acknowledgementNumber = (incoming.sequence + payload.byteLength) >>> 0;
							pendingChunks.push(new Uint8Array(payload));
							pendingLength += payload.byteLength;
						}
					}

					if (incoming.flags & 0x01) {
						flush();
						acknowledgementNumber = (acknowledgementNumber + 1) >>> 0;
						writer.write(buildTcpFrame(0x11)).catch(() => { });
						const controller = streamController;
						if (controller) {
							try { controller.close() } catch (e) { }
						}
						close();
						return;
					}

					if (bufferedBytes.byteLength < 4 || pendingLength >= 32768) flush();
				}
			} catch (error) {
				const controller = streamController;
				if (controller) {
					try { controller.error(error) } catch (e) { }
				}
				settleClosed(rejectClosed, error);
				try { socket?.close?.() } catch (e) { }
			}
		})();

		const writable = new WritableStream({
			async write(chunk) {
				const bytes = toUint8Array(chunk);
				if (!bytes.byteLength) return;
				if (bytes.byteLength <= SSTP_TCP_MSS) {
					await writer.write(buildTcpFrame(0x18, bytes));
					sequenceNumber = (sequenceNumber + bytes.byteLength) >>> 0;
					return;
				}
				const frames = [];
				for (let offset = 0; offset < bytes.byteLength; offset += SSTP_TCP_MSS) {
					const segment = bytes.subarray(offset, Math.min(offset + SSTP_TCP_MSS, bytes.byteLength));
					frames.push(buildTcpFrame(0x18, segment));
					sequenceNumber = (sequenceNumber + segment.byteLength) >>> 0;
				}
				await writer.write(concatByteChunks(...frames));
			},
			close() {
				return writer.write(buildTcpFrame(0x11)).catch(() => { });
			},
			abort(error) {
				close();
				if (error) settleClosed(rejectClosed, error);
			}
		});

		return { readable, writable, closed, close };
	} catch (error) {
		close();
		throw error;
	}
}
//////////////////////////////////////////////////订阅与传输配置（base64Secret / 传输参数 / Clash·Singbox·Surge 热补丁）///////////////////////////////////////////////
/**
 * 带秘钥的 Base64 编码
 * @param {string} plaintext - 原始明文字符串
 * @param {string} secret - 秘钥字符串（如 "KEY123"）
 * @returns {string} 经过秘钥处理的 Base64 字符串
 */
function base64SecretEncode(plaintext, secret) {
	const encoder = new TextEncoder();
	const data = encoder.encode(plaintext);
	const key = encoder.encode(secret);
	const mixed = new Uint8Array(data.length);

	for (let i = 0; i < data.length; i++) {
		mixed[i] = data[i] ^ key[i % key.length];
	}

	// 将 Uint8Array 转换为可被 btoa 处理的字符串
	let binary = '';
	for (let i = 0; i < mixed.length; i++) {
		binary += String.fromCharCode(mixed[i]);
	}
	return btoa(binary);
}

/**
 * 带秘钥的 Base64 解码
 * @param {string} encoded - 经秘钥处理过的 Base64 字符串
 * @param {string} secret - 秘钥字符串（必须与编码时相同）
 * @returns {string} 解码后的原始明文字符串
 */
function base64SecretDecode(encoded, secret) {
	const binary = atob(encoded);
	const mixed = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		mixed[i] = binary.charCodeAt(i);
	}

	const encoder = new TextEncoder();
	const key = encoder.encode(secret);
	const data = new Uint8Array(mixed.length);

	for (let i = 0; i < mixed.length; i++) {
		data[i] = mixed[i] ^ key[i % key.length];
	}

	const decoder = new TextDecoder();
	return decoder.decode(data);
}

function getTransportConfig(cfg = {}) {
	const isGrpc = cfg.transport === 'grpc';
	const [identityHeader, identityKey] = getIdentity(cfg.UUID);
	const xhttpPaddingJson = {
		"xPaddingObfsMode": true,
		"xPaddingMethod": "tokenish",
		"xPaddingPlacement": "queryInHeader",
		"xPaddingHeader": identityHeader,
		"xPaddingKey": identityKey
	};
	return {
		type: isGrpc ? (cfg.grpcMode === 'multi' ? 'grpc&mode=multi' : 'grpc&mode=gun') : (cfg.transport === 'xhttp' ? `xhttp&mode=stream-one&extra=${encodeURIComponent(JSON.stringify(xhttpPaddingJson))}` : 'ws'),
		pathFieldName: isGrpc ? 'serviceName' : 'path',
		hostFieldName: isGrpc ? 'authority' : 'host'
	};
}

function getTransportPathValue(cfg = {}, nodePath = '/', asBestSubGenerator = false) {
	const pathValue = asBestSubGenerator ? '/' : (cfg.randomPath ? randomPath(nodePath) : nodePath);
	if (cfg.transport !== 'grpc') return pathValue;
	return pathValue.split('?')[0] || '/';
}

function log(...args) {
	if (debugLogging) console.log(...args);
}

function applyClashPatch(clashRawContent, config_JSON = {}) {
	const uuid = config_JSON?.UUID || null;
	const echEnabled = Boolean(config_JSON?.ECH);
	const HOSTS = Array.isArray(config_JSON?.HOSTS) ? [...config_JSON.HOSTS] : [];
	const ECH_SNI = config_JSON?.ECHConfig?.SNI || null;
	const ECH_DNS = config_JSON?.ECHConfig?.DNS;
	const needsEchPatch = Boolean(uuid && echEnabled);
	const gRPCUserAgent = (typeof config_JSON?.gRPCUserAgent === 'string' && config_JSON.gRPCUserAgent.trim()) ? config_JSON.gRPCUserAgent.trim() : null;
	const needsGrpcPatch = config_JSON?.transport === "grpc" && Boolean(gRPCUserAgent);
	const gRPCUserAgentYAML = gRPCUserAgent ? JSON.stringify(gRPCUserAgent) : null;
	let clash_yaml = clashRawContent.replace(/mode:\s*Rule\b/g, 'mode: rule');

	const baseDnsBlock = `dns:
  enable: true
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
    - 114.114.114.114
  use-hosts: true
  nameserver:
    - https://sm2.doh.pub/dns-query
    - https://dns.alidns.com/dns-query
  fallback:
    - 8.8.4.4
    - 208.67.220.220
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4
      - 127.0.0.1/32
      - 0.0.0.0/32
    domain:
      - '+.google.com'
      - '+.facebook.com'
      - '+.youtube.com'
`;

	const addInlineGrpcUserAgent = (text) => text.replace(/grpc-opts:\s*\{([\s\S]*?)\}/i, (all, inner) => {
		if (/grpc-user-agent\s*:/i.test(inner)) return all;
		let content = inner.trim();
		if (content.endsWith(',')) content = content.slice(0, -1).trim();
		const patchedContent = content ? `${content}, grpc-user-agent: ${gRPCUserAgentYAML}` : `grpc-user-agent: ${gRPCUserAgentYAML}`;
		return `grpc-opts: {${patchedContent}}`;
	});
	const matchesGrpcNetwork = (text) => /(?:^|[,{])\s*network:\s*(?:"grpc"|'grpc'|grpc)(?=\s*(?:[,}\n#]|$))/mi.test(text);
	const getNodeProxyType = (nodeText) => nodeText.match(/type:\s*(\w+)/)?.[1] || 'vless';
	const getCredentialValue = (nodeText, isFlowStyle) => {
		const credentialField = getNodeProxyType(nodeText) === 'trojan' ? 'password' : 'uuid';
		const pattern = new RegExp(`${credentialField}:\\s*${isFlowStyle ? '([^,}\\n]+)' : '([^\\n]+)'}`);
		return nodeText.match(pattern)?.[1]?.trim() || null;
	};
	const insertNameserverPolicy = (yaml, hostsEntries) => {
		if (/^\s{2}nameserver-policy:\s*(?:\n|$)/m.test(yaml)) {
			return yaml.replace(/^(\s{2}nameserver-policy:\s*\n)/m, `$1${hostsEntries}\n`);
		}
		const lines = yaml.split('\n');
		let dnsBlockEndIndex = -1;
		let inDnsBlock = false;
		for (let i = 0; i < lines.length; i++) {
			const line = lines[i];
			if (/^dns:\s*$/.test(line)) {
				inDnsBlock = true;
				continue;
			}
			if (inDnsBlock && /^[a-zA-Z]/.test(line)) {
				dnsBlockEndIndex = i;
				break;
			}
		}
		const nameserverPolicyBlock = `  nameserver-policy:\n${hostsEntries}`;
		if (dnsBlockEndIndex !== -1) lines.splice(dnsBlockEndIndex, 0, nameserverPolicyBlock);
		else lines.push(nameserverPolicyBlock);
		return lines.join('\n');
	};
	const addFlowStyleGrpcUserAgent = (nodeText) => {
		if (!matchesGrpcNetwork(nodeText) || /grpc-user-agent\s*:/i.test(nodeText)) return nodeText;
		if (/grpc-opts:\s*\{/i.test(nodeText)) return addInlineGrpcUserAgent(nodeText);
		return nodeText.replace(/\}(\s*)$/, `, grpc-opts: {grpc-user-agent: ${gRPCUserAgentYAML}}}$1`);
	};
	const addBlockStyleGrpcUserAgent = (nodeLines, topLevelIndent) => {
		const topIndent = ' '.repeat(topLevelIndent);
		let grpcOptsIndex = -1;
		for (let idx = 0; idx < nodeLines.length; idx++) {
			const line = nodeLines[idx];
			if (!line.trim()) continue;
			const indent = line.search(/\S/);
			if (indent !== topLevelIndent) continue;
			if (/^\s*grpc-opts:\s*(?:#.*)?$/.test(line) || /^\s*grpc-opts:\s*\{.*\}\s*(?:#.*)?$/.test(line)) {
				grpcOptsIndex = idx;
				break;
			}
		}
		if (grpcOptsIndex === -1) {
			let insertIndex = -1;
			for (let j = nodeLines.length - 1; j >= 0; j--) {
				if (nodeLines[j].trim()) {
					insertIndex = j;
					break;
				}
			}
			if (insertIndex >= 0) nodeLines.splice(insertIndex + 1, 0, `${topIndent}grpc-opts:`, `${topIndent}  grpc-user-agent: ${gRPCUserAgentYAML}`);
			return nodeLines;
		}
		const grpcLine = nodeLines[grpcOptsIndex];
		if (/^\s*grpc-opts:\s*\{.*\}\s*(?:#.*)?$/.test(grpcLine)) {
			if (!/grpc-user-agent\s*:/i.test(grpcLine)) nodeLines[grpcOptsIndex] = addInlineGrpcUserAgent(grpcLine);
			return nodeLines;
		}
		let blockEndIndex = nodeLines.length;
		let childIndent = topLevelIndent + 2;
		let hasGrpcUserAgent = false;
		for (let idx = grpcOptsIndex + 1; idx < nodeLines.length; idx++) {
			const line = nodeLines[idx];
			const trimmed = line.trim();
			if (!trimmed) continue;
			const indent = line.search(/\S/);
			if (indent <= topLevelIndent) {
				blockEndIndex = idx;
				break;
			}
			if (indent > topLevelIndent && childIndent === topLevelIndent + 2) childIndent = indent;
			if (/^grpc-user-agent\s*:/.test(trimmed)) {
				hasGrpcUserAgent = true;
				break;
			}
		}
		if (!hasGrpcUserAgent) nodeLines.splice(blockEndIndex, 0, `${' '.repeat(childIndent)}grpc-user-agent: ${gRPCUserAgentYAML}`);
		return nodeLines;
	};
	const addBlockStyleEchOpts = (nodeLines, topLevelIndent) => {
		let insertIndex = -1;
		for (let j = nodeLines.length - 1; j >= 0; j--) {
			if (nodeLines[j].trim()) {
				insertIndex = j;
				break;
			}
		}
		if (insertIndex < 0) return nodeLines;
		const indent = ' '.repeat(topLevelIndent);
		const echOptsLines = [`${indent}ech-opts:`, `${indent}  enable: true`];
		if (ECH_SNI) echOptsLines.push(`${indent}  query-server-name: ${ECH_SNI}`);
		nodeLines.splice(insertIndex + 1, 0, ...echOptsLines);
		return nodeLines;
	};

	if (!/^dns:\s*(?:\n|$)/m.test(clash_yaml)) clash_yaml = baseDnsBlock + clash_yaml;
	if (ECH_SNI && !HOSTS.includes(ECH_SNI)) HOSTS.push(ECH_SNI);

	if (echEnabled && HOSTS.length > 0) {
		const hostsEntries = HOSTS.map(host => `    "${host}": ${ECH_DNS ? ECH_DNS : ''}`).join('\n');
		clash_yaml = insertNameserverPolicy(clash_yaml, hostsEntries);
	}

	if (!needsEchPatch && !needsGrpcPatch) return clash_yaml;

	const lines = clash_yaml.split('\n');
	const processedLines = [];
	let i = 0;

	while (i < lines.length) {
		const line = lines[i];
		const trimmedLine = line.trim();

		if (trimmedLine.startsWith('- {')) {
			let fullNode = line;
			let braceCount = (line.match(/\{/g) || []).length - (line.match(/\}/g) || []).length;
			while (braceCount > 0 && i + 1 < lines.length) {
				i++;
				fullNode += '\n' + lines[i];
				braceCount += (lines[i].match(/\{/g) || []).length - (lines[i].match(/\}/g) || []).length;
			}
			if (needsGrpcPatch) fullNode = addFlowStyleGrpcUserAgent(fullNode);
			if (needsEchPatch && getCredentialValue(fullNode, true) === uuid.trim()) {
				fullNode = fullNode.replace(/\}(\s*)$/, `, ech-opts: {enable: true${ECH_SNI ? `, query-server-name: ${ECH_SNI}` : ''}}}$1`);
			}
			processedLines.push(fullNode);
			i++;
		} else if (trimmedLine.startsWith('- name:')) {
			let nodeLines = [line];
			let baseIndent = line.search(/\S/);
			let topLevelIndent = baseIndent + 2;
			i++;
			while (i < lines.length) {
				const nextLine = lines[i];
				const nextTrimmed = nextLine.trim();
				if (!nextTrimmed) {
					nodeLines.push(nextLine);
					i++;
					break;
				}
				const nextIndent = nextLine.search(/\S/);
				if (nextIndent <= baseIndent && nextTrimmed.startsWith('- ')) {
					break;
				}
				if (nextIndent < baseIndent && nextTrimmed) {
					break;
				}
				nodeLines.push(nextLine);
				i++;
			}
			let nodeText = nodeLines.join('\n');
			if (needsGrpcPatch && matchesGrpcNetwork(nodeText)) {
				nodeLines = addBlockStyleGrpcUserAgent(nodeLines, topLevelIndent);
				nodeText = nodeLines.join('\n');
			}
			if (needsEchPatch && getCredentialValue(nodeText, false) === uuid.trim()) nodeLines = addBlockStyleEchOpts(nodeLines, topLevelIndent);
			processedLines.push(...nodeLines);
		} else {
			processedLines.push(line);
			i++;
		}
	}

	return processedLines.join('\n');
}

async function applySingboxPatch(singboxRawContent, config_JSON = {}) {
	const uuid = config_JSON?.UUID || null;
	const fingerprint = config_JSON?.Fingerprint || "chrome";
	const echEnabled = Boolean(config_JSON?.ECH);
	const ECH_SNI = config_JSON?.ECHConfig?.SNI || "cloudflare-ech.com";
	const sb_json_text = singboxRawContent.replace('1.1.1.1', '8.8.8.8').replace('1.0.0.1', '8.8.4.4');
	try {
		const config = JSON.parse(sb_json_text);
		const asArray = value => value === undefined || value === null ? [] : (Array.isArray(value) ? value : [value]);
		const ensureRoute = () => config.route = config.route && typeof config.route === 'object' ? config.route : {};
		const getDnsRuleServer = rule => rule && typeof rule === 'object' && !Array.isArray(rule) && typeof rule.server === 'string' ? rule.server : null;
		const addRuleSet = (type, code) => {
			if (!code || typeof code !== 'string') return null;
			const route = ensureRoute(), tag = `${type}-${code}`, ruleSet = Array.isArray(route.rule_set) ? route.rule_set : asArray(route.rule_set);
			if (!ruleSet.some(item => item?.tag === tag)) {
				const legacyOptions = type === 'geoip' ? route.geoip : route.geosite;
				ruleSet.push({ tag, type: 'remote', format: 'binary', url: `https://raw.githubusercontent.com/SagerNet/sing-${type}/rule-set/${tag}.srs`, ...(legacyOptions?.download_detour ? { download_detour: legacyOptions.download_detour } : {}) });
				config.experimental = config.experimental && typeof config.experimental === 'object' ? config.experimental : {};
				config.experimental.cache_file = config.experimental.cache_file && typeof config.experimental.cache_file === 'object' ? config.experimental.cache_file : {};
				config.experimental.cache_file.enabled ??= true;
			}
			route.rule_set = ruleSet;
			return tag;
		};

		const migrateRuleSetFields = rule => {
			if (!rule || typeof rule !== 'object' || Array.isArray(rule)) return rule;
			if (rule.type === 'logical' && Array.isArray(rule.rules)) {
				rule.rules = rule.rules.map(migrateRuleSetFields);
				return rule;
			}
			const tags = [];
			for (const geoip of asArray(rule.geoip)) {
				if (typeof geoip !== 'string') continue;
				if (geoip.toLowerCase() === 'private') rule.ip_is_private = true;
				else tags.push(addRuleSet('geoip', geoip));
			}
			for (const sourceGeoip of asArray(rule.source_geoip)) {
				if (typeof sourceGeoip !== 'string') continue;
				tags.push(addRuleSet('geoip', sourceGeoip));
				rule.rule_set_ip_cidr_match_source = true;
			}
			for (const geosite of asArray(rule.geosite)) if (typeof geosite === 'string') tags.push(addRuleSet('geosite', geosite));
			if (tags.length) rule.rule_set = [...new Set([...asArray(rule.rule_set), ...tags].filter(Boolean))];
			delete rule.geoip;
			delete rule.source_geoip;
			delete rule.geosite;
			return rule;
		};

		const migrateDnsRules = (rule, rcodeServerMap) => {
			rule = migrateRuleSetFields(rule);
			if (!rule || typeof rule !== 'object' || Array.isArray(rule)) return rule;
			if (rule.type === 'logical' && Array.isArray(rule.rules)) {
				rule.rules = rule.rules.map(childRule => migrateDnsRules(childRule, rcodeServerMap));
				return rule;
			}
			const serverTag = getDnsRuleServer(rule);
			if (serverTag && rcodeServerMap.has(serverTag)) {
				for (const key of ['server', 'strategy', 'disable_cache', 'rewrite_ttl', 'client_subnet', 'timeout']) delete rule[key];
				rule.action = 'predefined';
				rule.rcode = rcodeServerMap.get(serverTag);
			} else if (serverTag && !rule.action) rule.action = 'route';
			return rule;
		};

		if (Array.isArray(config.inbounds)) {
			for (const inbound of config.inbounds) {
				if (!inbound || typeof inbound !== 'object' || inbound.type !== 'tun') continue;
				for (const migration of [
					{ targetKey: 'address', sourceKeys: ['inet4_address', 'inet6_address'] },
					{ targetKey: 'route_address', sourceKeys: ['inet4_route_address', 'inet6_route_address'] },
					{ targetKey: 'route_exclude_address', sourceKeys: ['inet4_route_exclude_address', 'inet6_route_exclude_address'] }
				]) {
					const values = asArray(inbound[migration.targetKey]);
					for (const sourceKey of migration.sourceKeys) values.push(...asArray(inbound[sourceKey]));
					if (values.length) inbound[migration.targetKey] = [...new Set(values)];
					for (const sourceKey of migration.sourceKeys) delete inbound[sourceKey];
				}
				if (inbound.tag) {
					const addedRules = [];
					if (inbound.domain_strategy) addedRules.push({ inbound: inbound.tag, action: 'resolve', strategy: inbound.domain_strategy });
					if (inbound.sniff) {
						const sniffRule = { inbound: inbound.tag, action: 'sniff' };
						if (inbound.sniff_timeout) sniffRule.timeout = inbound.sniff_timeout;
						addedRules.push(sniffRule);
					}
					if (addedRules.length) {
						const route = ensureRoute();
						route.rules = [...addedRules, ...asArray(route.rules)];
					}
				}
				delete inbound.sniff;
				delete inbound.sniff_timeout;
				delete inbound.domain_strategy;
			}
		}

		if (config?.route && typeof config.route === 'object' && Array.isArray(config.route.rules)) {
			const patchRouteRule = rule => {
				rule = migrateRuleSetFields(rule);
				if (rule?.type === 'logical' && Array.isArray(rule.rules)) rule.rules = rule.rules.map(patchRouteRule);
				else if (rule && typeof rule === 'object' && !Array.isArray(rule) && rule.outbound && !rule.action) rule.action = 'route';
				return rule;
			};
			config.route.rules = config.route.rules.map(patchRouteRule);
		}

		const dns = config?.dns;
		if (dns && typeof dns === 'object') {
			const legacyFakeIP = dns.fakeip && typeof dns.fakeip === 'object' ? dns.fakeip : null;
			const rcodeServerMap = new Map();
			const DNS_SCHEME_TYPES = { 'tcp:': 'tcp', 'udp:': 'udp', 'tls:': 'tls', 'quic:': 'quic', 'https:': 'https', 'h3:': 'h3' };
			const RCODE_MAP = { success: 'NOERROR', format_error: 'FORMERR', server_failure: 'SERVFAIL', name_error: 'NXDOMAIN', not_implemented: 'NOTIMP', refused: 'REFUSED' };
			let hasFakeIPServer = false;

			if (Array.isArray(dns.servers)) {
				const migratedServers = [];
				for (const originalServer of dns.servers) {
					if (!originalServer || typeof originalServer !== 'object' || Array.isArray(originalServer)) {
						migratedServers.push(originalServer);
						continue;
					}

					const server = { ...originalServer };
					let parsedAddress = null, parsedRCode = '', rawAddress = typeof server.address === 'string' ? server.address.trim() : '';
					if (rawAddress) {
						const lowerAddress = rawAddress.toLowerCase();
						if (lowerAddress === 'fakeip') parsedAddress = { type: 'fakeip' };
						else if (lowerAddress === 'local') parsedAddress = { type: 'local' };
						else if (lowerAddress.startsWith('rcode://')) {
							parsedAddress = { type: 'rcode' };
							parsedRCode = rawAddress.slice('rcode://'.length).toLowerCase();
						}
						else if (lowerAddress.startsWith('dhcp://')) {
							const dhcpInterface = rawAddress.slice('dhcp://'.length);
							parsedAddress = dhcpInterface && dhcpInterface.toLowerCase() !== 'auto' ? { type: 'dhcp', interface: dhcpInterface } : { type: 'dhcp' };
						} else {
							try {
								const addressURL = new URL(rawAddress);
								const type = DNS_SCHEME_TYPES[addressURL.protocol.toLowerCase()];
								if (type) {
									const parsedServer = addressURL.hostname?.startsWith('[') && addressURL.hostname.endsWith(']') ? addressURL.hostname.slice(1, -1) : addressURL.hostname;
									parsedAddress = {
										type,
										server: parsedServer || addressURL.host || rawAddress,
										...(addressURL.port ? { server_port: Number(addressURL.port) } : {}),
										...((type === 'https' || type === 'h3') && addressURL.pathname && addressURL.pathname !== '/dns-query' ? { path: addressURL.pathname } : {})
									};
								}
							} catch (_) { }
							if (!parsedAddress) parsedAddress = { type: 'udp', server: rawAddress };
						}
					}

					if (parsedAddress?.type === 'rcode') {
						const rcode = RCODE_MAP[parsedRCode] || 'NOERROR';
						if (typeof server.tag === 'string' && server.tag) {
							rcodeServerMap.set(server.tag, rcode);
							rcodeServerMap.set(server.tag.startsWith('dns_') ? server.tag.slice(4) : `dns_${server.tag}`, rcode);
						}
						continue;
					}

					if (parsedAddress) {
						delete server.address;
						Object.assign(server, parsedAddress);
					}
					if (server.address_resolver !== undefined && server.domain_resolver === undefined) server.domain_resolver = server.address_resolver;
					if (server.address_strategy !== undefined && server.domain_strategy === undefined) server.domain_strategy = server.address_strategy;
					delete server.address_resolver;
					delete server.address_strategy;
					if (server.detour === 'DIRECT') delete server.detour;

					if (server.type === 'fakeip') {
						hasFakeIPServer = true;
						if (legacyFakeIP) {
							for (const key of ['inet4_range', 'inet6_range']) {
								if (legacyFakeIP[key] !== undefined && server[key] === undefined) server[key] = legacyFakeIP[key];
							}
						}
					}
					migratedServers.push(server);
				}
				dns.servers = migratedServers;
			}

			if (legacyFakeIP && !hasFakeIPServer && legacyFakeIP.enabled !== false) {
				const fakeIPServer = { type: 'fakeip', tag: 'fakeip' };
				for (const rule of Array.isArray(dns.rules) ? dns.rules : []) {
					const serverTag = getDnsRuleServer(rule);
					if (serverTag && serverTag.toLowerCase().includes('fakeip')) {
						fakeIPServer.tag = serverTag;
						break;
					}
				}
				for (const key of ['inet4_range', 'inet6_range']) {
					if (legacyFakeIP[key] !== undefined) fakeIPServer[key] = legacyFakeIP[key];
				}
				if (Array.isArray(dns.servers)) dns.servers.push(fakeIPServer);
				else dns.servers = [fakeIPServer];
			}

			if (Array.isArray(dns.rules)) {
				const migratedRules = [];
				for (const rule of dns.rules) {
					const serverTag = getDnsRuleServer(rule);
					const outbound = asArray(rule?.outbound);
					const DNS_ROUTE_OPTION_KEYS = new Set(['outbound', 'server', 'action', 'strategy', 'disable_cache', 'rewrite_ttl', 'client_subnet', 'timeout']);
					const isOutboundAnyDNSRule = rule && typeof rule === 'object' && !Array.isArray(rule) && rule.type !== 'logical'
						&& serverTag && outbound.includes('any') && Object.keys(rule).every(key => DNS_ROUTE_OPTION_KEYS.has(key));
					if (isOutboundAnyDNSRule) {
						const route = ensureRoute();
						if (route.default_domain_resolver === undefined) {
							const resolver = { server: serverTag };
							for (const key of ['strategy', 'disable_cache', 'rewrite_ttl', 'client_subnet', 'timeout']) {
								if (rule[key] !== undefined) resolver[key] = rule[key];
							}
							route.default_domain_resolver = Object.keys(resolver).length === 1 ? resolver.server : resolver;
						}
						continue;
					}
					migratedRules.push(migrateDnsRules(rule, rcodeServerMap));
				}
				dns.rules = migratedRules;
			}

			delete dns.fakeip;
			delete dns.independent_cache;
		}

		if (config?.route && typeof config.route === 'object') {
			delete config.route.geoip;
			delete config.route.geosite;
		}
		if (config?.ntp?.detour === 'DIRECT') delete config.ntp.detour;

		if (Array.isArray(config.outbounds)) {
			const outboundTags = new Set(config.outbounds.map(outbound => outbound?.tag).filter(Boolean));
			const referencesReject = value => value === 'REJECT' || (value && typeof value === 'object' && (Array.isArray(value) ? value.some(referencesReject) : Object.values(value).some(referencesReject)));
			if (!outboundTags.has('REJECT') && referencesReject({ outbounds: config.outbounds, route: config.route })) config.outbounds.push({ type: 'block', tag: 'REJECT' });
		}

		// --- UUID 匹配节点的 TLS 热补丁 (utls & ech) ---
		if (uuid) {
			config.outbounds?.forEach(outbound => {
				// 仅处理包含 uuid 或 password 且匹配的节点
				if ((outbound.uuid && outbound.uuid === uuid) || (outbound.password && outbound.password === uuid)) {
					// 确保 tls 对象存在
					if (!outbound.tls) {
						outbound.tls = { enabled: true };
					}

					// 添加/更新 utls 配置
					if (fingerprint) {
						outbound.tls.utls = {
							enabled: true,
							fingerprint: fingerprint
						};
					}

					// 如果提供了 ech_config，添加/更新 ech 配置
					if (echEnabled) {
						outbound.tls.ech = {
							enabled: true,
							query_server_name: ECH_SNI,// 等待 1.13.0+ 版本上线
							//config: `-----BEGIN ECH CONFIGS-----\n${ech_config}\n-----END ECH CONFIGS-----`
						};
					}
				}
			});
		}

		return JSON.stringify(config, null, 2);
	} catch (e) {
		console.error("Singbox热补丁执行失败:", e);
		return JSON.stringify(JSON.parse(sb_json_text), null, 2);
	}
}

function applySurgePatch(content, url, config_JSON) {
	const lineList = content.includes('\r\n') ? content.split('\r\n') : content.split('\n');
	const fullNodePath = config_JSON.randomPath ? randomPath(config_JSON.fullNodePath) : config_JSON.fullNodePath;
	let outputContent = "";
	for (let x of lineList) {
		if (x.includes('= trojan,') && !x.includes('ws=true') && !x.includes('ws-path=')) {
			const host = x.split("sni=")[1].split(",")[0];
			const beforeContent = `sni=${host}, skip-cert-verify=${config_JSON.skipCertVerify}`;
			const afterContent = `sni=${host}, skip-cert-verify=${config_JSON.skipCertVerify}, ws=true, ws-path=${fullNodePath.replace(/,/g, '%2C')}, ws-headers=Host:"${host}"`;
			outputContent += x.replace(new RegExp(beforeContent, 'g'), afterContent).replace("[", "").replace("]", "") + '\n';
		} else {
			outputContent += x + '\n';
		}
	}

	outputContent = `#!MANAGED-CONFIG ${url} interval=${config_JSON.bestSubGen.SUBUpdateTime * 60 * 60} strict=false` + outputContent.substring(outputContent.indexOf('\n'));
	return outputContent;
}

///////////////////////////////////////////////////////日志与通用工具（KV 日志 / 掩码 / MD5MD5 / 随机路径）///////////////////////////////////////////////
async function writeRequestLog(env, request, clientIP, requestType = "Get_SUB", config_JSON, writeKvLog = true) {
	try {
		const now = new Date();
		const logEntry = { TYPE: requestType, IP: clientIP, ASN: `AS${request.cf.asn || '0'} ${request.cf.asOrganization || 'Unknown'}`, CC: `${request.cf.country || 'N/A'} ${request.cf.city || 'N/A'}`, URL: request.url, UA: request.headers.get('User-Agent') || 'Unknown', TIME: now.getTime() };
		if (config_JSON.TG.enabled) {
			try {
				const TG_TXT = await env.KV.get('tg.json');
				const TG_JSON = JSON.parse(TG_TXT);
				if (TG_JSON?.BotToken && TG_JSON?.ChatID) {
					const requestTime = new Date(logEntry.TIME).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
					const requestUrl = new URL(logEntry.URL);
					const msg = `<b>#${config_JSON.bestSubGen.SUBNAME} 日志通知</b>\n\n` +
						`📌 <b>类型：</b>#${logEntry.TYPE}\n` +
						`🌐 <b>IP：</b><code>${logEntry.IP}</code>\n` +
						`📍 <b>位置：</b>${logEntry.CC}\n` +
						`🏢 <b>ASN：</b>${logEntry.ASN}\n` +
						`🔗 <b>域名：</b><code>${requestUrl.host}</code>\n` +
						`🔍 <b>路径：</b><code>${requestUrl.pathname + requestUrl.search}</code>\n` +
						`🤖 <b>UA：</b><code>${logEntry.UA}</code>\n` +
						`📅 <b>时间：</b>${requestTime}\n` +
						`${config_JSON.CF.Usage.success ? `📊 <b>请求用量：</b>${config_JSON.CF.Usage.total}/${config_JSON.CF.Usage.max} <b>${((config_JSON.CF.Usage.total / config_JSON.CF.Usage.max) * 100).toFixed(2)}%</b>\n` : ''}`;
					await fetch(`https://api.telegram.org/bot${TG_JSON.BotToken}/sendMessage?chat_id=${TG_JSON.ChatID}&parse_mode=HTML&text=${encodeURIComponent(msg)}`, {
						method: 'GET',
						headers: {
							'Accept': 'text/html,application/xhtml+xml,application/xml;',
							'Accept-Encoding': 'gzip, deflate, br',
							'User-Agent': logEntry.UA || 'Unknown',
						}
					});
				}
			} catch (error) { console.error(`读取tg.json出错: ${error.message}`) }
		}
		writeKvLog = ['1', 'true'].includes(env.OFF_LOG) ? false : writeKvLog;
		if (!writeKvLog) return;
		let logArray = [];
		const existingLogs = await env.KV.get('log.json'), KV_SIZE_LIMIT_MB = 4;//MB
		if (existingLogs) {
			try {
				logArray = JSON.parse(existingLogs);
				if (!Array.isArray(logArray)) { logArray = [logEntry] }
				else if (requestType !== "Get_SUB") {
					const thirtyMinAgoTs = now.getTime() - 30 * 60 * 1000;
					if (logArray.some(log => log.TYPE !== "Get_SUB" && log.IP === clientIP && log.URL === request.url && log.UA === (request.headers.get('User-Agent') || 'Unknown') && log.TIME >= thirtyMinAgoTs)) return;
					logArray.push(logEntry);
					while (JSON.stringify(logArray, null, 2).length > KV_SIZE_LIMIT_MB * 1024 * 1024 && logArray.length > 0) logArray.shift();
				} else {
					logArray.push(logEntry);
					while (JSON.stringify(logArray, null, 2).length > KV_SIZE_LIMIT_MB * 1024 * 1024 && logArray.length > 0) logArray.shift();
				}
			} catch (e) { logArray = [logEntry] }
		} else { logArray = [logEntry] }
		await env.KV.put('log.json', JSON.stringify(logArray, null, 2));
	} catch (error) { console.error(`日志记录失败: ${error.message}`) }
}

function maskSensitive(text, prefixLen = 3, suffixLen = 2) {
	if (!text || typeof text !== 'string') return text;
	if (text.length <= prefixLen + suffixLen) return text; // 如果长度太短，直接返回

	const prefix = text.slice(0, prefixLen);
	const suffix = text.slice(-suffixLen);
	const starCount = text.length - prefixLen - suffixLen;

	return `${prefix}${'*'.repeat(starCount)}${suffix}`;
}

// 双重 MD5：md5(hex(md5(input))[7:27])，CF Workers 的 crypto.subtle 支持 MD5（标准 WebCrypto 不支持）。
// 用于管理页 cookie、订阅 token 等派生——改动会令已登录会话与已分发订阅失效。
async function MD5MD5(text) {
	const encoder = new TextEncoder();

	const firstHash = await crypto.subtle.digest('MD5', encoder.encode(text));
	const firstHashArr = Array.from(new Uint8Array(firstHash));
	const firstHex = firstHashArr.map(bytes => bytes.toString(16).padStart(2, '0')).join('');

	const secondHash = await crypto.subtle.digest('MD5', encoder.encode(firstHex.slice(7, 27)));
	const secondHashArr = Array.from(new Uint8Array(secondHash));
	const secondHex = secondHashArr.map(bytes => bytes.toString(16).padStart(2, '0')).join('');

	return secondHex.toLowerCase();
}

function randomPath(fullNodePath = "/") {
	const COMMON_PATH_SEGMENTS = ["about", "account", "acg", "act", "activity", "ad", "ads", "ajax", "album", "albums", "anime", "api", "app", "apps", "archive", "archives", "article", "articles", "ask", "auth", "avatar", "bbs", "bd", "blog", "blogs", "book", "books", "bt", "buy", "cart", "category", "categories", "cb", "channel", "channels", "chat", "china", "city", "class", "classify", "clip", "clips", "club", "cn", "code", "collect", "collection", "comic", "comics", "community", "company", "config", "contact", "content", "course", "courses", "cp", "data", "detail", "details", "dh", "directory", "discount", "discuss", "dl", "dload", "doc", "docs", "document", "documents", "doujin", "download", "downloads", "drama", "edu", "en", "ep", "episode", "episodes", "event", "events", "f", "faq", "favorite", "favourites", "favs", "feedback", "file", "files", "film", "films", "forum", "forums", "friend", "friends", "game", "games", "gif", "go", "go.html", "go.php", "group", "groups", "help", "home", "hot", "htm", "html", "image", "images", "img", "index", "info", "intro", "item", "items", "ja", "jp", "jump", "jump.html", "jump.php", "jumping", "knowledge", "lang", "lesson", "lessons", "lib", "library", "link", "links", "list", "live", "lives", "m", "mag", "magnet", "mall", "manhua", "map", "member", "members", "message", "messages", "mobile", "movie", "movies", "music", "my", "new", "news", "note", "novel", "novels", "online", "order", "out", "out.html", "out.php", "outbound", "p", "page", "pages", "pay", "payment", "pdf", "photo", "photos", "pic", "pics", "picture", "pictures", "play", "player", "playlist", "post", "posts", "product", "products", "program", "programs", "project", "qa", "question", "rank", "ranking", "read", "readme", "redirect", "redirect.html", "redirect.php", "reg", "register", "res", "resource", "retrieve", "sale", "search", "season", "seasons", "section", "seller", "series", "service", "services", "setting", "settings", "share", "shop", "show", "shows", "site", "soft", "sort", "source", "special", "star", "stars", "static", "stock", "store", "stream", "streaming", "streams", "student", "study", "tag", "tags", "task", "teacher", "team", "tech", "temp", "test", "thread", "tool", "tools", "topic", "topics", "torrent", "trade", "travel", "tv", "txt", "type", "u", "upload", "uploads", "url", "urls", "user", "users", "v", "version", "videos", "view", "vip", "vod", "watch", "web", "wenku", "wiki", "work", "www", "zh", "zh-cn", "zh-tw", "zip"];
	const randomNum = Math.floor(Math.random() * 3 + 1);
	const randomPath = COMMON_PATH_SEGMENTS.sort(() => 0.5 - Math.random()).slice(0, randomNum).join('/');
	if (fullNodePath === "/") return `/${randomPath}`;
	else return `/${randomPath + fullNodePath.replace('/?', '?')}`;
}

function replaceAsterisks(content) {
	if (typeof content !== 'string' || !content.includes('*')) return content;
	const charset = 'abcdefghijklmnopqrstuvwxyz0123456789';
	return content.replace(/\*/g, () => {
		let s = '';
		for (let i = 0; i < Math.floor(Math.random() * 14) + 3; i++) s += charset[Math.floor(Math.random() * charset.length)];
		return s;
	});
}

const dohCache = {};
///////////////////////////////////////////////////////DoH 查询与本地缓存（预加载竞速 / ProxyIP TXT 解析依赖）///////////////////////////////////////////////
const DOH_CACHE_MAX_ENTRIES = 256;
const DOH_RECORD_TYPE_MAP = { A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, AAAA: 28, SRV: 33, HTTPS: 65 };
async function dohQuery(domain, recordType, dohResolver = "https://cloudflare-dns.com/dns-query") {
	const normalizeDomain = String(domain || '').trim().toLowerCase().replace(/\.$/, '');
	const normalizeRecordType = String(recordType || '').trim().toUpperCase();
	const cacheKey = `${normalizeDomain}:${normalizeRecordType}`;
	const qtype = DOH_RECORD_TYPE_MAP[normalizeRecordType] || 1;
	const currentTs = Date.now();
	const existingCacheEntry = dohCache[cacheKey];
	if (existingCacheEntry && currentTs < existingCacheEntry.expireTime) {
		log(`[DoH查询] 命中缓存 ${domain} ${recordType} via ${dohResolver}`);
		return existingCacheEntry.data.map(data => ({ type: qtype, data }));
	}
	const startTime = performance.now();
	log(`[DoH查询] 开始查询 ${domain} ${recordType} via ${dohResolver}`);
	try {
		// 记录类型字符串转数值
		// 编码域名为 DNS wire format labels
		const encodeDomainName = (name) => {
			const parts = name.endsWith('.') ? name.slice(0, -1).split('.') : name.split('.');
			const bufs = [];
			for (const label of parts) {
				const enc = new TextEncoder().encode(label);
				bufs.push(new Uint8Array([enc.length]), enc);
			}
			bufs.push(new Uint8Array([0]));
			const total = bufs.reduce((s, b) => s + b.length, 0);
			const result = new Uint8Array(total);
			let off = 0;
			for (const b of bufs) { result.set(b, off); off += b.length }
			return result;
		};

		// 构建 DNS 查询报文
		const qname = encodeDomainName(normalizeDomain);
		const query = new Uint8Array(12 + qname.length + 4);
		const qview = new DataView(query.buffer);
		qview.setUint16(0, crypto.getRandomValues(new Uint16Array(1))[0]); // ID (random per RFC 1035)
		qview.setUint16(2, 0x0100);  // Flags: RD=1 (递归查询)
		qview.setUint16(4, 1);       // QDCOUNT
		query.set(qname, 12);
		qview.setUint16(12 + qname.length, qtype);
		qview.setUint16(12 + qname.length + 2, 1); // QCLASS = IN

		// 通过 POST 发送 dns-message 请求
		log(`[DoH查询] 发送查询报文 ${domain} via ${dohResolver} (type=${qtype}, ${query.length}字节)`);
		const response = await fetch(dohResolver, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/dns-message',
				'Accept': 'application/dns-message',
			},
			body: query,
		});
		if (!response.ok) {
			console.warn(`[DoH查询] 请求失败 ${domain} ${recordType} via ${dohResolver} 响应代码:${response.status}`);
			return [];
		}

		// 解析 DNS 响应报文
		const buf = new Uint8Array(await response.arrayBuffer());
		const dv = new DataView(buf.buffer);
		const qdcount = dv.getUint16(4);
		const ancount = dv.getUint16(6);
		log(`[DoH查询] 收到响应 ${domain} ${recordType} via ${dohResolver} (${buf.length}字节, ${ancount}条应答)`);

		// 解析域名（处理指针压缩）
		const parseDomainName = (pos) => {
			const labels = [];
			let p = pos, jumped = false, endPos = -1, safe = 128;
			while (p < buf.length && safe-- > 0) {
				const len = buf[p];
				if (len === 0) { if (!jumped) endPos = p + 1; break }
				if ((len & 0xC0) === 0xC0) {
					if (!jumped) endPos = p + 2;
					p = ((len & 0x3F) << 8) | buf[p + 1];
					jumped = true;
					continue;
				}
				labels.push(new TextDecoder().decode(buf.slice(p + 1, p + 1 + len)));
				p += len + 1;
			}
			if (endPos === -1) endPos = p + 1;
			return [labels.join('.'), endPos];
		};

		// 跳过 Question Section
		let offset = 12;
		for (let i = 0; i < qdcount; i++) {
			const [, end] = parseDomainName(offset);
			offset = /** @type {number} */ (end) + 4; // +4 跳过 QTYPE + QCLASS
		}

		// 解析 Answer Section
		const answers = [];
		for (let i = 0; i < ancount && offset < buf.length; i++) {
			const [name, nameEnd] = parseDomainName(offset);
			offset = /** @type {number} */ (nameEnd);
			const type = dv.getUint16(offset); offset += 2;
			offset += 2; // CLASS
			const ttl = dv.getUint32(offset); offset += 4;
			const rdlen = dv.getUint16(offset); offset += 2;
			const rdata = buf.slice(offset, offset + rdlen);
			offset += rdlen;

			let data;
			if (type === 1 && rdlen === 4) {
				// A 记录
				data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
			} else if (type === 28 && rdlen === 16) {
				// AAAA 记录
				const segs = [];
				for (let j = 0; j < 16; j += 2) segs.push(((rdata[j] << 8) | rdata[j + 1]).toString(16));
				data = segs.join(':');
			} else if (type === 16) {
				// TXT 记录 (长度前缀字符串)
				let tOff = 0;
				const parts = [];
				while (tOff < rdlen) {
					const tLen = rdata[tOff++];
					parts.push(new TextDecoder().decode(rdata.slice(tOff, tOff + tLen)));
					tOff += tLen;
				}
				data = parts.join('');
			} else if (type === 5) {
				// CNAME 记录
				const [cname] = parseDomainName(offset - rdlen);
				data = cname;
			} else {
				data = Array.from(rdata).map(b => b.toString(16).padStart(2, '0')).join('');
			}
			answers.push({ name, type, TTL: ttl, data, rdata });
		}
		const elapsedMs = (performance.now() - startTime).toFixed(2);
		log(`[DoH查询] 查询完成 ${domain} ${recordType} via ${dohResolver} ${elapsedMs}ms 共${answers.length}条结果${answers.length > 0 ? '\n' + answers.map((a, i) => `  ${i + 1}. ${a.name} type=${a.type} TTL=${a.TTL} data=${a.data}`).join('\n') : ''}`);
		// DoH 缓存至少保留 5 分钟，响应 TTL 更长时尊重响应 TTL；空响应使用 5 分钟负缓存
		const relatedRecords = answers.filter(answer => answer.type === qtype);
		const minTtl = relatedRecords.length > 0 ? Math.min(...relatedRecords.map(a => a.TTL)) : 0;
		const cacheTtl = Math.max(minTtl, 5 * 60);
		const cacheExpireTime = Date.now() + cacheTtl * 1000;
		const cachedData = relatedRecords.map(answer => answer.data);
		if (cachedData.length > 0 || answers.length === 0) {
			if (Object.keys(dohCache).length >= DOH_CACHE_MAX_ENTRIES) {
				const cleanupTs = Date.now();
				for (const [cacheEntryKey, cacheEntry] of Object.entries(dohCache)) {
					if (cleanupTs >= cacheEntry.expireTime) delete dohCache[cacheEntryKey];
				}
				if (Object.keys(dohCache).length >= DOH_CACHE_MAX_ENTRIES) {
					delete dohCache[Object.keys(dohCache)[0]];
				}
			}
			dohCache[cacheKey] = { data: cachedData, expireTime: cacheExpireTime };
			log(`[DoH查询] 写入缓存 ${domain} ${recordType} TTL=${cacheTtl}s${cachedData.length === 0 ? '（空结果）' : ''}`);
		}
		return answers;
	} catch (error) {
		const elapsedMs = (performance.now() - startTime).toFixed(2);
		console.error(`[DoH查询] 查询失败 ${domain} ${recordType} via ${dohResolver} ${elapsedMs}ms:`, error);
		return [];
	}
}

///////////////////////////////////////////////////////配置键名迁移与 loadConfig///////////////////////////////////////////////
// 内部统一使用英文键；外部管理页（edt-pages）仍按历史中文键读写。
// KV 中可能存有旧版中文键配置：读入时转英文，返回给管理页时再转回中文。
const CONFIG_KEY_CN_TO_EN = {
	"TLS分片": "tlsFragment", "gRPC模式": "grpcMode", "为空": "isEmpty", "代理全局": "proxyGlobal",
	"代理参数": "proxyParams", "代理类型": "proxyType", "代理账号": "proxyAccount", "优选订阅生成": "bestSubGen",
	"传输协议": "transport", "停止并刷新": "stopAndFlush", "入站候选加密配置": "inboundCandidateCrypto", "入站解密器": "inboundDecryptor",
	"全局": "global", "关闭连接": "closeConnection", "写入": "write", "写入并等待": "writeAndWait",
	"初始化CF_JSON": "defaultCfJson", "初始化TG_JSON": "defaultTgJson", "加密并发送": "encryptAndSend", "加密方式": "encryptionMethod",
	"加密配置": "cryptoConfig", "加载时间": "loadTime", "协议": "protocol", "协议类型": "protocolType",
	"原始数据": "rawData", "反代": "proxy", "反代IP": "proxyIP", "反代Socket": "proxySocket",
	"反代兜底": "proxyFallback", "反代地址": "proxyAddr", "反代查询参数": "proxySearchParams", "发送": "send",
	"合包": "coalesce", "名称": "queueName", "启用": "enabled", "启用0RTT": "enable0RTT",
	"响应帧列表": "responseFrames", "回包Socket": "replySocket", "域名字段名": "hostFieldName", "字节数": "byteCount",
	"完整节点路径": "fullNodePath", "封装结果": "wrappedResult", "指定端口": "fixedPort", "排序后数组": "sortedArray",
	"收纳": "absorb", "数组化": "asArray", "最终木马结果": "finalTrojanResult", "最终魏烈思结果": "finalVlessResult",
	"木马反代地址": "trojanProxyAddr", "木马结果": "trojanResult", "本地IP库": "localIPPool", "条目数": "entryCount",
	"查询参数运营商": "queryParamIsp", "查询数组": "queryArray", "标准": "standard", "清空": "clear",
	"状态": "status", "白名单": "whitelist", "目标主机": "targetHost", "目标端口": "targetPort",
	"直接发送": "sendDirectly", "相关记录": "relatedRecords", "等待空": "waitIdle", "结束": "end",
	"结果": "result", "缓存": "cache", "获取SOCKS5账号": "getSocks5Account", "获取写入器": "getWriter",
	"获取连接任务": "getConnectTask", "订阅转换配置": "subConverterConfig", "请求URL文本": "requestUrlText", "账号": "account",
	"路径字段名": "pathFieldName", "路径模板": "pathTemplates", "跳过证书验证": "skipCertVerify", "输入": "input",
	"过期时间": "expireTime", "释放写入器": "releaseWriter", "重试连接": "retryConnect", "链式代理地址": "chainProxyAddr",
	"随机IP": "randomIP", "随机数量": "randomCount", "随机路径": "randomPath", "首包已建立": "firstPacketEstablished",
	"魏烈思结果": "vlessResult",
};

const CONFIG_KEY_EN_TO_CN = {
	"absorb": "收纳", "account": "账号", "asArray": "数组化", "bestSubGen": "优选订阅生成",
	"byteCount": "字节数", "cache": "缓存", "chainProxyAddr": "链式代理地址", "clear": "清空",
	"closeConnection": "关闭连接", "coalesce": "合包", "cryptoConfig": "加密配置", "defaultCfJson": "初始化CF_JSON",
	"defaultTgJson": "初始化TG_JSON", "enable0RTT": "启用0RTT", "enabled": "启用", "encryptAndSend": "加密并发送",
	"encryptionMethod": "加密方式", "end": "结束", "entryCount": "条目数", "expireTime": "过期时间",
	"finalTrojanResult": "最终木马结果", "finalVlessResult": "最终魏烈思结果", "firstPacketEstablished": "首包已建立", "fixedPort": "指定端口",
	"fullNodePath": "完整节点路径", "getConnectTask": "获取连接任务", "getSocks5Account": "获取SOCKS5账号", "getWriter": "获取写入器",
	"global": "全局", "grpcMode": "gRPC模式", "hostFieldName": "域名字段名", "inboundCandidateCrypto": "入站候选加密配置",
	"inboundDecryptor": "入站解密器", "input": "输入", "isEmpty": "为空", "loadTime": "加载时间",
	"localIPPool": "本地IP库", "pathFieldName": "路径字段名", "pathTemplates": "路径模板", "protocol": "协议",
	"protocolType": "协议类型", "proxy": "反代", "proxyAccount": "代理账号", "proxyAddr": "反代地址",
	"proxyFallback": "反代兜底", "proxyGlobal": "代理全局", "proxyIP": "反代IP", "proxyParams": "代理参数",
	"proxySearchParams": "反代查询参数", "proxySocket": "反代Socket", "proxyType": "代理类型", "queryArray": "查询数组",
	"queryParamIsp": "查询参数运营商", "queueName": "名称", "randomCount": "随机数量", "randomIP": "随机IP",
	"randomPath": "随机路径", "rawData": "原始数据", "relatedRecords": "相关记录", "releaseWriter": "释放写入器",
	"replySocket": "回包Socket", "requestUrlText": "请求URL文本", "responseFrames": "响应帧列表", "result": "结果",
	"retryConnect": "重试连接", "send": "发送", "sendDirectly": "直接发送", "skipCertVerify": "跳过证书验证",
	"sortedArray": "排序后数组", "standard": "标准", "status": "状态", "stopAndFlush": "停止并刷新",
	"subConverterConfig": "订阅转换配置", "targetHost": "目标主机", "targetPort": "目标端口", "tlsFragment": "TLS分片",
	"transport": "传输协议", "trojanProxyAddr": "木马反代地址", "trojanResult": "木马结果", "vlessResult": "魏烈思结果",
	"waitIdle": "等待空", "whitelist": "白名单", "wrappedResult": "封装结果", "write": "写入",
	"writeAndWait": "写入并等待",
};

// 就地深度迁移对象键名（仅重命名 map 中出现的键，递归进入数组与嵌套对象）
function migrateConfigKeysDeep(value, map) {
	if (!value || typeof value !== 'object') return value;
	if (Array.isArray(value)) {
		for (let i = 0; i < value.length; i++) value[i] = migrateConfigKeysDeep(value[i], map);
		return value;
	}
	for (const key of Object.keys(value)) {
		const mapped = map[key];
		if (mapped !== undefined && mapped !== key) {
			value[mapped] = migrateConfigKeysDeep(value[key], map);
			delete value[key];
		} else {
			value[key] = migrateConfigKeysDeep(value[key], map);
		}
	}
	return value;
}

// 深拷贝并转回管理页使用的中文键。禁止就地修改：config_JSON 是跨请求复用的模块级状态
function toLegacyConfig(config) {
	return migrateConfigKeysDeep(JSON.parse(JSON.stringify(config)), CONFIG_KEY_EN_TO_CN);
}

// 读取并规范化 config.json：中文键迁移为英文键、补齐缺省、计算 fullNodePath/LINK/TOKEN，
// 结果写入模块级 config_JSON（全局状态，见文件头）并返回。副作用：必要时向 KV 写入默认配置。
async function loadConfig(env, hostname, userID, UA = "Mozilla/5.0", resetConfig = false) {
	const _p = BRAND_PROXYIP;
	const host = hostname, Ali_DoH = "https://dns.alidns.com/dns-query", ECH_SNI = "cloudflare-ech.com", placeholder = '{{IP:PORT}}', initStartTime = performance.now(), defaultConfigJson = {
		TIME: new Date().toISOString(),
		HOST: host,
		HOSTS: [hostname],
		UUID: userID,
		PATH: "/",
		ALPN: "",
		protocolType: "vless",
		transport: "ws",
		grpcMode: "gun",
		gRPCUserAgent: UA,
		skipCertVerify: false,
		enable0RTT: false,
		tlsFragment: null,
		randomPath: false,
		ECH: false,
		ECHConfig: {
			DNS: Ali_DoH,
			SNI: ECH_SNI,
		},
		SS: {
			encryptionMethod: "aes-128-gcm",
			TLS: true,
		},
		Fingerprint: "chrome",
		bestSubGen: {
			local: true, // true: 基于本地的优选地址  false: 优选订阅生成器
			localIPPool: {
				randomIP: true, // 当 随机IP 为true时生效，启用随机IP的数量，否则使用KV内的ADD.txt
				randomCount: 16,
				fixedPort: -1,
			},
			SUB: null,
			SUBNAME: "edgetunnel",
			SUBUpdateTime: 3, // 订阅更新时间（小时）
			TOKEN: await MD5MD5(hostname + userID),
		},
		subConverterConfig: {
			SUBAPI: `https://SUBAPI.${BRAND_OWNER}ssss.net`,
			SUBCONFIG: `https://raw.githubusercontent.com/${BRAND_OWNER}/ACL4SSR/refs/heads/main/Clash/config/ACL4SSR_Online_Mini_MultiMode_CF.ini`,
			SUBEMOJI: false,
			SUBLIST: false, //仅输出节点信息
			UDP: false, // 启用 UDP
			XUDP: false, // 启用 XUDP
			TLS13: false, // 启用 TLS 1.3
			APPEND_TYPE: false, // 插入节点类型
			SORT: false, // 基础节点排序
			EXPAND: true, // 展开规则全文
		},
		proxy: {
			[_p]: "auto",
			SOCKS5: {
				enabled: null,
				global: false,
				account: '',
				whitelist: socks5Whitelist,
			},
			pathTemplates: {
				[_p]: "proxyip=" + placeholder,
				SOCKS5: {
					global: "socks5://" + placeholder,
					standard: "socks5=" + placeholder
				},
				HTTP: {
					global: "http://" + placeholder,
					standard: "http=" + placeholder
				},
				HTTPS: {
					global: "https://" + placeholder,
					standard: "https=" + placeholder
				},
				TURN: {
					global: "turn://" + placeholder,
					standard: "turn=" + placeholder
				},
				SSTP: {
					global: "sstp://" + placeholder,
					standard: "sstp=" + placeholder
				},
			},
		},
		TG: {
			enabled: false,
			BotToken: null,
			ChatID: null,
		},
		CF: {
			Email: null,
			GlobalAPIKey: null,
			AccountID: null,
			APIToken: null,
			UsageAPI: null,
			Usage: {
				success: false,
				pages: 0,
				workers: 0,
				total: 0,
				max: 100000,
			},
		}
	};

	try {
		let configJSON = await env.KV.get('config.json');
		if (!configJSON || resetConfig == true) {
			await env.KV.put('config.json', JSON.stringify(defaultConfigJson, null, 2));
			config_JSON = defaultConfigJson;
		} else {
			config_JSON = JSON.parse(configJSON);
			migrateConfigKeysDeep(config_JSON, CONFIG_KEY_CN_TO_EN);
		}
	} catch (error) {
		console.error(`读取config_JSON出错: ${error.message}`);
		config_JSON = defaultConfigJson;
	}

	if (!config_JSON.subConverterConfig.SUBLIST) config_JSON.subConverterConfig.SUBLIST = false;
	if (!config_JSON.subConverterConfig.UDP) config_JSON.subConverterConfig.UDP = false;
	if (!config_JSON.subConverterConfig.XUDP) config_JSON.subConverterConfig.XUDP = false;
	if (!config_JSON.subConverterConfig.TLS13) config_JSON.subConverterConfig.TLS13 = false;
	if (!config_JSON.subConverterConfig.APPEND_TYPE) config_JSON.subConverterConfig.APPEND_TYPE = false;
	if (!config_JSON.subConverterConfig.SORT) config_JSON.subConverterConfig.SORT = false;
	if (typeof config_JSON.subConverterConfig.EXPAND !== 'boolean') config_JSON.subConverterConfig.EXPAND = true;
	if (!config_JSON.gRPCUserAgent) config_JSON.gRPCUserAgent = UA;
	config_JSON.HOST = host;
	if (!config_JSON.HOSTS) config_JSON.HOSTS = [hostname];
	if (env.HOST) config_JSON.HOSTS = (await ensureArray(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]);
	config_JSON.UUID = userID;
	if (!config_JSON.randomPath) config_JSON.randomPath = false;
	if (!config_JSON.enable0RTT) config_JSON.enable0RTT = false;

	if (env.PATH) config_JSON.PATH = env.PATH.startsWith('/') ? env.PATH : '/' + env.PATH;
	else if (!config_JSON.PATH) config_JSON.PATH = '/';
	if (!config_JSON.ALPN) config_JSON.ALPN = "";

	if (!config_JSON.grpcMode) config_JSON.grpcMode = 'gun';
	if (!config_JSON.SS) config_JSON.SS = { encryptionMethod: "aes-128-gcm", TLS: false };

	if (!config_JSON.proxy.pathTemplates?.[_p]) {
		config_JSON.proxy.pathTemplates = {
			[_p]: "proxyip=" + placeholder,
			SOCKS5: {
				global: "socks5://" + placeholder,
				standard: "socks5=" + placeholder
			},
			HTTP: {
				global: "http://" + placeholder,
				standard: "http=" + placeholder
			},
			HTTPS: {
				global: "https://" + placeholder,
				standard: "https=" + placeholder
			},
			TURN: {
				global: "turn://" + placeholder,
				standard: "turn=" + placeholder
			},
			SSTP: {
				global: "sstp://" + placeholder,
				standard: "sstp=" + placeholder
			},
		};
	}
	if (!config_JSON.proxy.pathTemplates.HTTPS) config_JSON.proxy.pathTemplates.HTTPS = { global: "https://" + placeholder, standard: "https=" + placeholder };
	if (!config_JSON.proxy.pathTemplates.TURN) config_JSON.proxy.pathTemplates.TURN = { global: "turn://" + placeholder, standard: "turn=" + placeholder };
	if (!config_JSON.proxy.pathTemplates.SSTP) config_JSON.proxy.pathTemplates.SSTP = { global: "sstp://" + placeholder, standard: "sstp=" + placeholder };

	const proxyConfig = config_JSON.proxy.pathTemplates[config_JSON.proxy.SOCKS5.enabled?.toUpperCase()];

	let pathProxyParams = '';
	if (proxyConfig && config_JSON.proxy.SOCKS5.account) pathProxyParams = (config_JSON.proxy.SOCKS5.global ? proxyConfig.global : proxyConfig.standard).replace(placeholder, config_JSON.proxy.SOCKS5.account);
	else if (config_JSON.proxy[_p] !== 'auto') pathProxyParams = config_JSON.proxy.pathTemplates[_p].replace(placeholder, config_JSON.proxy[_p]);

	let proxySearchParams = '';
	if (pathProxyParams.includes('?')) {
		const [proxyPathPart, proxyQueryPart] = pathProxyParams.split('?');
		pathProxyParams = proxyPathPart;
		proxySearchParams = proxyQueryPart;
	}

	config_JSON.PATH = config_JSON.PATH.replace(pathProxyParams, '').replace('//', '/');
	const normalizedPath = config_JSON.PATH === '/' ? '' : config_JSON.PATH.replace(/\/+(?=\?|$)/, '').replace(/\/+$/, '');
	const [pathPart, ...queryArray] = normalizedPath.split('?');
	const queryPart = queryArray.length ? '?' + queryArray.join('?') : '';
	const finalQueryPart = proxySearchParams ? (queryPart ? queryPart + '&' + proxySearchParams : '?' + proxySearchParams) : queryPart;
	config_JSON.fullNodePath = (pathPart || '/') + (pathPart && pathProxyParams ? '/' : '') + pathProxyParams + finalQueryPart + (config_JSON.enable0RTT ? (finalQueryPart ? '&' : '?') + 'ed=2560' : '');

	if (!config_JSON.tlsFragment && config_JSON.tlsFragment !== null) config_JSON.tlsFragment = null;
	const tlsFragmentParams = config_JSON.tlsFragment == 'Shadowrocket' ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : config_JSON.tlsFragment == 'Happ' ? `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
	if (!config_JSON.Fingerprint) config_JSON.Fingerprint = "chrome";
	if (!config_JSON.ECH) config_JSON.ECH = false;
	if (!config_JSON.ECHConfig) config_JSON.ECHConfig = { DNS: Ali_DoH, SNI: ECH_SNI };
	const echLinkParams = config_JSON.ECH ? `&ech=${encodeURIComponent((config_JSON.ECHConfig.SNI ? config_JSON.ECHConfig.SNI + '+' : '') + config_JSON.ECHConfig.DNS)}` : '';
	const { type: transport, pathFieldName, hostFieldName } = getTransportConfig(config_JSON);
	const transportPathValue = getTransportPathValue(config_JSON, config_JSON.fullNodePath);
	config_JSON.LINK = config_JSON.protocolType === 'ss'
		? `${config_JSON.protocolType}://${btoa(config_JSON.SS.encryptionMethod + ':' + userID)}@${host}:${config_JSON.SS.TLS ? '443' : '80'}?plugin=v2${encodeURIComponent(`ray-plugin;mode=websocket;host=${host};path=${((config_JSON.fullNodePath.includes('?') ? config_JSON.fullNodePath.replace('?', '?enc=' + config_JSON.SS.encryptionMethod + '&') : (config_JSON.fullNodePath + '?enc=' + config_JSON.SS.encryptionMethod)) + (config_JSON.SS.TLS ? ';tls' : ''))};mux=0`) + echLinkParams}#${encodeURIComponent(config_JSON.bestSubGen.SUBNAME)}`
		: `${config_JSON.protocolType}://${userID}@${host}:443?security=tls&type=${transport + echLinkParams}&${hostFieldName}=${host}&fp=${config_JSON.Fingerprint}&sni=${host}&${pathFieldName}=${encodeURIComponent(transportPathValue) + tlsFragmentParams}&encryption=none#${encodeURIComponent(config_JSON.bestSubGen.SUBNAME)}`;
	config_JSON.bestSubGen.TOKEN = await MD5MD5(hostname + userID);

	const defaultTgJson = { BotToken: null, ChatID: null };
	config_JSON.TG = { enabled: config_JSON.TG.enabled ? config_JSON.TG.enabled : false, ...defaultTgJson };
	try {
		const TG_TXT = await env.KV.get('tg.json');
		if (!TG_TXT) {
			await env.KV.put('tg.json', JSON.stringify(defaultTgJson, null, 2));
		} else {
			const TG_JSON = JSON.parse(TG_TXT);
			config_JSON.TG.ChatID = TG_JSON.ChatID ? TG_JSON.ChatID : null;
			config_JSON.TG.BotToken = TG_JSON.BotToken ? maskSensitive(TG_JSON.BotToken) : null;
		}
	} catch (error) {
		console.error(`读取tg.json出错: ${error.message}`);
	}

	const defaultCfJson = { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null, UsageAPI: null };
	config_JSON.CF = { ...defaultCfJson, Usage: { success: false, pages: 0, workers: 0, total: 0, max: 100000 } };
	try {
		const CF_TXT = await env.KV.get('cf.json');
		if (!CF_TXT) {
			await env.KV.put('cf.json', JSON.stringify(defaultCfJson, null, 2));
		} else {
			const CF_JSON = JSON.parse(CF_TXT);
			if (CF_JSON.UsageAPI) {
				try {
					const response = await fetch(CF_JSON.UsageAPI);
					const Usage = await response.json();
					config_JSON.CF.Usage = Usage;
				} catch (err) {
					console.error(`请求 CF_JSON.UsageAPI 失败: ${err.message}`);
				}
			} else {
				config_JSON.CF.Email = CF_JSON.Email ? CF_JSON.Email : null;
				config_JSON.CF.GlobalAPIKey = CF_JSON.GlobalAPIKey ? maskSensitive(CF_JSON.GlobalAPIKey) : null;
				config_JSON.CF.AccountID = CF_JSON.AccountID ? maskSensitive(CF_JSON.AccountID) : null;
				config_JSON.CF.APIToken = CF_JSON.APIToken ? maskSensitive(CF_JSON.APIToken) : null;
				config_JSON.CF.UsageAPI = null;
				const Usage = await getCloudflareUsage(CF_JSON.Email, CF_JSON.GlobalAPIKey, CF_JSON.AccountID, CF_JSON.APIToken);
				config_JSON.CF.Usage = Usage;
			}
		}
	} catch (error) {
		console.error(`读取cf.json出错: ${error.message}`);
	}

	config_JSON.loadTime = (performance.now() - initStartTime).toFixed(2) + 'ms';
	return config_JSON;
}

///////////////////////////////////////////////////////ISP 识别与优选 IP（运营商 CIDR / 随机 IP / 优选 API）///////////////////////////////////////////////
function detectISP(request) {
	const cf = request?.cf;
	const ASN_ISP_MAP = {
		'4134': 'ct',
		'4809': 'ct',
		'4811': 'ct',
		'4812': 'ct',
		'4815': 'ct',
		'4837': 'cu',
		'4814': 'cu',
		'9929': 'cu',
		'17623': 'cu',
		'17816': 'cu',
		'9808': 'cmcc',
		'24400': 'cmcc',
		'56040': 'cmcc',
		'56041': 'cmcc',
		'56044': 'cmcc',
	};
	const ISP_KEYWORD_MAP = [
		{ code: 'ct', pattern: /chinanet|chinatelecom|china telecom|cn2|shtel/ },
		{ code: 'cmcc', pattern: /cmi|cmnet|chinamobile|china mobile|cmcc|mobile communications/ },
		{ code: 'cu', pattern: /china169|china unicom|chinaunicom|cucc|cncgroup|cuii|netcom/ },
	];
	if (String(cf?.country || '').toLowerCase() !== 'cn') return 'cf';
	const orgName = String(cf?.asOrganization || '').toLowerCase();
	const ispHit = ISP_KEYWORD_MAP.find(({ pattern }) => pattern.test(orgName))?.code;
	return ispHit || ASN_ISP_MAP[String(cf?.asn || '')] || 'cf';
}

async function generateRandomIPs(request, count = 16, fixedPort = -1) {
	const url = new URL(request.url);
	const queryParamIsp = String(url.searchParams.get('cnIspCode') || '').toLowerCase();
	const ispFileId = ['ct', 'cu', 'cmcc', 'cf'].includes(queryParamIsp) ? queryParamIsp : detectISP(request);
	const ISP_NAME_MAP = {
		cmcc: 'CF移动优选',
		cu: 'CF联通优选',
		ct: 'CF电信优选',
		cf: 'CF官方优选',
	};
	const cidr_url = ispFileId === 'cf' ? `https://raw.githubusercontent.com/${BRAND_OWNER}/${BRAND_OWNER}/main/CF-CIDR.txt` : `https://raw.githubusercontent.com/${BRAND_OWNER}/${BRAND_OWNER}/main/CF-CIDR/${ispFileId}.txt`;
	const cfname = ISP_NAME_MAP[ispFileId] || 'CF官方优选';
	const cfport = [443, 2053, 2083, 2087, 2096, 8443];
	let cidrList = [];
	try { const res = await fetch(cidr_url); cidrList = res.ok ? await ensureArray(await res.text()) : ['104.16.0.0/13'] } catch { cidrList = ['104.16.0.0/13'] }

	const generateRandomIPFromCIDR = (cidr) => {
		const [baseIP, prefixLength] = cidr.split('/'), prefix = parseInt(prefixLength), hostBits = 32 - prefix;
		const ipInt = baseIP.split('.').reduce((a, p, i) => a | (parseInt(p) << (24 - i * 8)), 0);
		const randomOffset = Math.floor(Math.random() * Math.pow(2, hostBits));
		const mask = (0xFFFFFFFF << hostBits) >>> 0, randomIP = (((ipInt & mask) >>> 0) + randomOffset) >>> 0;
		return [(randomIP >>> 24) & 0xFF, (randomIP >>> 16) & 0xFF, (randomIP >>> 8) & 0xFF, randomIP & 0xFF].join('.');
	};
	const randomIPs = Array.from({ length: count }, (_, index) => {
		const ip = generateRandomIPFromCIDR(cidrList[Math.floor(Math.random() * cidrList.length)]);
		const targetPort = fixedPort === -1
			? cfport[Math.floor(Math.random() * cfport.length)]
			: fixedPort;
		return `${ip}:${targetPort}#${cfname}${index + 1}`;
	});
	return [randomIPs, randomIPs.join('\n')];
}

async function ensureArray(content) {
	var replacedContent = content.replace(/[	"'\r\n]+/g, ',').replace(/,+/g, ',');
	if (replacedContent.charAt(0) == ',') replacedContent = replacedContent.slice(1);
	if (replacedContent.charAt(replacedContent.length - 1) == ',') replacedContent = replacedContent.slice(0, replacedContent.length - 1);
	const addressArray = replacedContent.split(',');
	return addressArray;
}

async function fetchBestSubGeneratorData(bestSubGeneratorHost, uid = "000000") {
	let bestIP = [], otherNodeLinks = '', formatHost = bestSubGeneratorHost.replace(/^sub:\/\//i, 'https://').split('#')[0].split('?')[0];
	if (!/^https?:\/\//i.test(formatHost)) formatHost = `https://${formatHost}`;

	try {
		const url = new URL(formatHost);
		formatHost = url.origin;
	} catch (error) {
		bestIP.push(`127.0.0.1:1234#${bestSubGeneratorHost}优选订阅生成器格式化异常:${error.message}`);
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
					let addrPort = addressMatch[1], remark = ''; // 域名:端口 或 IP:端口
					const remarkMatch = lineContent.match(/#(.+)$/);
					if (remarkMatch) remark = '#' + decodeURIComponent(remarkMatch[1]);
					bestIP.push(addrPort + remark);
				}
			} else {
				otherNodeLinks += lineContent + '\n';
			}
		}
	} catch (error) {
		bestIP.push(`127.0.0.1:1234#${bestSubGeneratorHost}优选订阅生成器异常:${error.message}`);
	}

	return [bestIP, otherNodeLinks];
}

async function fetchBestIPApi(urls, defaultPort = '443', uid = "000000", timeoutMs = 3000) {
	if (!urls?.length) return [[], [], [], []];
	const results = new Set(), proxyIPPool = new Set();
	let subResponsePlainLinks = '', needsSubConverterUrls = [];
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
						if (bestIPAsProxyIP) proxyIPPool.add(ip.split('#')[0]);
					}
				} else {
					for (const ip of bestIP) {
						results.add(ip);
						if (bestIPAsProxyIP) proxyIPPool.add(ip.split('#')[0]);
					}
				}
				// 处理第二个数组 - 其他节点LINK
				if (otherNodeLinks && typeof otherNodeLinks === 'string' && apiRemarkName) {
					const processedLinkContent = otherNodeLinks.replace(/([a-z][a-z0-9+\-.]*:\/\/[^\r\n]*?)(\r?\n|$)/gi, (match, link, lineEnd) => {
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
					const bytes = new Uint8Array(atob(cleanText).split('').map(c => c.charCodeAt(0)));
					preprocessedSubPlaintext = new TextDecoder('utf-8').decode(bytes);
				} catch { }
			}
			if (preprocessedSubPlaintext.split('#')[0].includes('://')) {
				// 处理LINK内容
				if (apiRemarkName) {
					const processedLinkContent = preprocessedSubPlaintext.replace(/([a-z][a-z0-9+\-.]*:\/\/[^\r\n]*?)(\r?\n|$)/gi, (match, link, lineEnd) => {
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
			const isCSV = lines.length > 1 && lines[0].includes(',');
			const IPV6_PATTERN = /^[^\[\]]*:[^\[\]]*:[^\[\]]/;
			const parsedUrl = new URL(urlWithoutHash);
			if (!isCSV) {
				lines.forEach(line => {
					const lineHashIndex = line.indexOf('#');
					const [hostPart, remark] = lineHashIndex > -1 ? [line.substring(0, lineHashIndex), line.substring(lineHashIndex)] : [line, ''];
					let hasPort = false;
					if (hostPart.startsWith('[')) {
						hasPort = /\]:(\d+)$/.test(hostPart);
					} else {
						const colonIndex = hostPart.lastIndexOf(':');
						hasPort = colonIndex > -1 && /^\d+$/.test(hostPart.substring(colonIndex + 1));
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
					if (bestIPAsProxyIP) proxyIPPool.add(ipItem.split('#')[0]);
				});
			} else {
				const headers = lines[0].split(',').map(h => h.trim());
				const dataLines = lines.slice(1);
				if (headers.includes('IP地址') && headers.includes('端口') && headers.includes('数据中心')) {
					const ipIdx = headers.indexOf('IP地址'), portIdx = headers.indexOf('端口');
					const remarkIdx = headers.indexOf('国家') > -1 ? headers.indexOf('国家') :
						headers.indexOf('城市') > -1 ? headers.indexOf('城市') : headers.indexOf('数据中心');
					const tlsIdx = headers.indexOf('TLS');
					dataLines.forEach(line => {
						const cols = line.split(',').map(c => c.trim());
						if (tlsIdx !== -1 && cols[tlsIdx]?.toLowerCase() !== 'true') return;
						const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
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
						const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
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

///////////////////////////////////////////////////////反代参数解析与 CF 用量///////////////////////////////////////////////
// 从 URL / KV 解析链式代理与 ProxyIP 反代参数，产出 forwardataTCP 使用的 proxyCtx。
async function getProxyParams(url, uuid, defaultProxyIP = '', defaultProxyFallback = true) {
	const { searchParams } = url;
	const pathname = decodeURIComponent(url.pathname);
	const pathLower = pathname.toLowerCase();
	let proxyIP = defaultProxyIP, enableSocks5Proxy = null, enableSocks5GlobalProxy = false, mySocks5Account = '', parsedSocks5Address = {}, enableProxyFallback = defaultProxyFallback;
	const proxyCtx = { trojanProxyAddr: null, proxyIP, proxyType: null, proxyAccount: '', proxyGlobal: false, proxyParams: {}, proxyFallback: enableProxyFallback };
	const saveSnapshot = () => {
		proxyCtx.proxyIP = proxyIP;
		proxyCtx.proxyType = enableSocks5Proxy;
		proxyCtx.proxyAccount = mySocks5Account;
		proxyCtx.proxyGlobal = enableSocks5GlobalProxy;
		proxyCtx.proxyParams = { ...parsedSocks5Address };
		proxyCtx.proxyFallback = enableProxyFallback;
	};

	const chainProxyPathMatch = pathname.match(/\/video\/(.+)$/i);
	if (chainProxyPathMatch) {
		try {
			const chainProxyPlaintext = base64SecretDecode(chainProxyPathMatch[1].replace(/\/+$/, ''), uuid);
			const { type, ...chainProxyAddr } = JSON.parse(chainProxyPlaintext);
			if (!type || !chainProxyDefaultPort[String(type).toLowerCase()]) throw new Error('链式代理类型无效');
			if (!chainProxyAddr.hostname || !chainProxyAddr.port) throw new Error('链式代理地址缺少 hostname 或 port');
			mySocks5Account = '';
			proxyIP = '链式代理';
			enableProxyFallback = false;
			enableSocks5GlobalProxy = true;
			enableSocks5Proxy = String(type).toLowerCase();
			parsedSocks5Address = {
				username: chainProxyAddr.username,
				password: chainProxyAddr.password,
				hostname: chainProxyAddr.hostname,
				port: Number(chainProxyAddr.port)
			};
			if (isNaN(parsedSocks5Address.port)) throw new Error('链式代理端口无效');
			saveSnapshot();
			return proxyCtx;
		} catch (err) {
			console.error('解析链式代理参数失败:', err.message);
		}
	}

	mySocks5Account = searchParams.get('socks5') || searchParams.get('http') || searchParams.get('https') || searchParams.get('turn') || searchParams.get('sstp') || null;
	enableSocks5GlobalProxy = searchParams.has('globalproxy');
	if (searchParams.get('socks5')) enableSocks5Proxy = 'socks5';
	else if (searchParams.get('http')) enableSocks5Proxy = 'http';
	else if (searchParams.get('https')) enableSocks5Proxy = 'https';
	else if (searchParams.get('turn')) enableSocks5Proxy = 'turn';
	else if (searchParams.get('sstp')) enableSocks5Proxy = 'sstp';

	const parseProxyUrl = (value, forceGlobal = true) => {
		const match = /^(socks5|http|https|turn|sstp):\/\/(.+)$/i.exec(value || '');
		if (!match) return false;
		enableSocks5Proxy = match[1].toLowerCase();
		mySocks5Account = match[2].split('/')[0];
		if (forceGlobal) enableSocks5GlobalProxy = true;
		return true;
	};

	const setProxyIP = (value) => {
		proxyIP = value;
		enableSocks5Proxy = null;
		enableProxyFallback = false;
	};

	const extractPathValue = (value) => {
		if (!value.includes('://')) {
			const slashIndex = value.indexOf('/');
			return slashIndex > 0 ? value.slice(0, slashIndex) : value;
		}
		const protocolSplit = value.split('://');
		if (protocolSplit.length !== 2) return value;
		const slashIndex = protocolSplit[1].indexOf('/');
		return slashIndex > 0 ? `${protocolSplit[0]}://${protocolSplit[1].slice(0, slashIndex)}` : value;
	};

	const trojanPathMatch = /\/trojan=([^?#\s]+)/i.exec(pathname);
	if (trojanPathMatch) {
		try {
			proxyCtx.trojanProxyAddr = parseTrojanProxyAddr(trojanPathMatch[1].replace(/\/+$/, ''));
		} catch (err) {
			console.error('解析木马反代地址失败:', err.message);
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
			const type = match[1].toLowerCase();
			enableSocks5Proxy = type === 'sock' || type === 'socks' ? 'socks5' : type;
			mySocks5Account = match[2].split('/')[0];
			enableSocks5GlobalProxy = true;
		} else if ((match = /\/(g?s5|socks5|g?http|g?https|g?turn|g?sstp)=([^/?#\s]+)/i.exec(pathname))) {
			const type = match[1].toLowerCase();
			mySocks5Account = match[2].split('/')[0];
			enableSocks5Proxy = type.includes('sstp') ? 'sstp' : (type.includes('turn') ? 'turn' : (type.includes('https') ? 'https' : (type.includes('http') ? 'http' : 'socks5')));
			if (type.startsWith('g')) enableSocks5GlobalProxy = true;
		} else if ((match = /\/(proxyip[.=]|pyip=|ip=)([^?#\s]+)/.exec(pathLower))) {
			const pathProxyValue = extractPathValue(match[2]);
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
		parsedSocks5Address = await getSocks5Account(mySocks5Account, getProxyDefaultPort(enableSocks5Proxy));
		if (searchParams.get('socks5')) enableSocks5Proxy = 'socks5';
		else if (searchParams.get('http')) enableSocks5Proxy = 'http';
		else if (searchParams.get('https')) enableSocks5Proxy = 'https';
		else if (searchParams.get('turn')) enableSocks5Proxy = 'turn';
		else if (searchParams.get('sstp')) enableSocks5Proxy = 'sstp';
		else enableSocks5Proxy = enableSocks5Proxy || 'socks5';
	} catch (err) {
		console.error('解析SOCKS5地址失败:', err.message);
		enableSocks5Proxy = null;
	}
	saveSnapshot();
	return proxyCtx;
}

const chainProxyDefaultPort = { socks5: 1080, http: 80, https: 443, turn: 3478, sstp: 443 };
function getProxyDefaultPort(type) {
	return chainProxyDefaultPort[String(type || '').toLowerCase()] || 80;
}

const SOCKS5_ACCOUNT_B64_RE = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i, IPV6_BRACKET_RE = /^\[.*\]$/;
function getSocks5Account(address, defaultPort = 80) {
	address = String(address || '').trim().replace(/^(socks5|http|https|turn|sstp):\/\//i, '').split('#')[0].trim();
	const firstAt = address.lastIndexOf("@");
	if (firstAt !== -1) {
		let auth = address.slice(0, firstAt).replaceAll("%3D", "=");
		if (!auth.includes(":") && SOCKS5_ACCOUNT_B64_RE.test(auth)) auth = atob(auth);
		address = `${auth}@${address.slice(firstAt + 1)}`;
	}

	const atIndex = address.lastIndexOf("@");
	const hostPart = (atIndex === -1 ? address : address.slice(atIndex + 1)).split('/')[0];
	const authPart = atIndex === -1 ? "" : address.slice(0, atIndex);
	const [username, password] = authPart ? authPart.split(":") : [];
	if (authPart && !password) throw new Error('无效的 SOCKS 地址格式：认证部分必须是 "username:password" 的形式');

	let hostname = hostPart, port = defaultPort;
	if (hostPart.includes("]:")) {
		const [ipv6Host, ipv6Port = ""] = hostPart.split("]:");
		hostname = ipv6Host + "]";
		port = Number(ipv6Port.replace(/[^\d]/g, ""));
	} else if (!hostPart.startsWith("[")) {
		const parts = hostPart.split(":");
		if (parts.length === 2) {
			hostname = parts[0];
			port = Number(parts[1].replace(/[^\d]/g, ""));
		}
	}

	if (isNaN(port)) throw new Error('无效的 SOCKS 地址格式：端口号必须是数字');
	if (hostname.includes(":") && !IPV6_BRACKET_RE.test(hostname)) throw new Error('无效的 SOCKS 地址格式：IPv6 地址必须用方括号括起来，如 [2001:db8::1]');
	return { username, password, hostname, port };
}

async function getCloudflareUsage(Email, GlobalAPIKey, AccountID, APIToken) {
	const API = "https://api.cloudflare.com/client/v4";
	const sum = (a) => a?.reduce((t, i) => t + (i?.sum?.requests || 0), 0) || 0;
	const cfg = { "Content-Type": "application/json" };

	try {
		if (!AccountID && (!Email || !GlobalAPIKey)) return { success: false, pages: 0, workers: 0, total: 0, max: 100000 };

		if (!AccountID) {
			const r = await fetch(`${API}/accounts`, {
				method: "GET",
				headers: { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey }
			});
			if (!r.ok) throw new Error(`账户获取失败: ${r.status}`);
			const d = await r.json();
			if (!d?.result?.length) throw new Error("未找到账户");
			const idx = d.result.findIndex(a => a.name?.toLowerCase().startsWith(Email.toLowerCase()));
			AccountID = d.result[idx >= 0 ? idx : 0]?.id;
		}

		const now = new Date();
		now.setUTCHours(0, 0, 0, 0);
		const hdr = APIToken ? { ...cfg, "Authorization": `Bearer ${APIToken}` } : { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey };

		const res = await fetch(`${API}/graphql`, {
			method: "POST",
			headers: hdr,
			body: JSON.stringify({
				query: `query getBillingMetrics($AccountID: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) {
					viewer { accounts(filter: {accountTag: $AccountID}) {
						pagesFunctionsInvocationsAdaptiveGroups(limit: 1000, filter: $filter) { sum { requests } }
						workersInvocationsAdaptive(limit: 10000, filter: $filter) { sum { requests } }
					} }
				}`,
				variables: { AccountID, filter: { datetime_geq: now.toISOString(), datetime_leq: new Date().toISOString() } }
			})
		});

		if (!res.ok) throw new Error(`查询失败: ${res.status}`);
		const result = await res.json();
		if (result.errors?.length) throw new Error(result.errors[0].message);

		const acc = result?.data?.viewer?.accounts?.[0];
		if (!acc) throw new Error("未找到账户数据");

		const pages = sum(acc.pagesFunctionsInvocationsAdaptiveGroups);
		const workers = sum(acc.workersInvocationsAdaptive);
		const total = pages + workers;
		const max = 100000;
		log(`统计结果 - Pages: ${pages}, Workers: ${workers}, 总计: ${total}, 上限: 100000`);
		return { success: true, pages, workers, total, max };

	} catch (error) {
		console.error('获取使用量错误:', error.message);
		return { success: false, pages: 0, workers: 0, total: 0, max: 100000 };
	}
}

function sha224(s) {
	const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
	const r = (n, b) => ((n >>> b) | (n << (32 - b))) >>> 0;
	s = unescape(encodeURIComponent(s));
	const l = s.length * 8; s += String.fromCharCode(0x80);
	while ((s.length * 8) % 512 !== 448) s += String.fromCharCode(0);
	const h = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
	const hi = Math.floor(l / 0x100000000), lo = l & 0xFFFFFFFF;
	s += String.fromCharCode((hi >>> 24) & 0xFF, (hi >>> 16) & 0xFF, (hi >>> 8) & 0xFF, hi & 0xFF, (lo >>> 24) & 0xFF, (lo >>> 16) & 0xFF, (lo >>> 8) & 0xFF, lo & 0xFF);
	const w = []; for (let i = 0; i < s.length; i += 4)w.push((s.charCodeAt(i) << 24) | (s.charCodeAt(i + 1) << 16) | (s.charCodeAt(i + 2) << 8) | s.charCodeAt(i + 3));
	for (let i = 0; i < w.length; i += 16) {
		const x = new Array(64).fill(0);
		for (let j = 0; j < 16; j++)x[j] = w[i + j];
		for (let j = 16; j < 64; j++) {
			const s0 = r(x[j - 15], 7) ^ r(x[j - 15], 18) ^ (x[j - 15] >>> 3);
			const s1 = r(x[j - 2], 17) ^ r(x[j - 2], 19) ^ (x[j - 2] >>> 10);
			x[j] = (x[j - 16] + s0 + x[j - 7] + s1) >>> 0;
		}
		let [a, b, c, d, e, f, g, h0] = h;
		for (let j = 0; j < 64; j++) {
			const S1 = r(e, 6) ^ r(e, 11) ^ r(e, 25), ch = (e & f) ^ (~e & g), t1 = (h0 + S1 + ch + K[j] + x[j]) >>> 0;
			const S0 = r(a, 2) ^ r(a, 13) ^ r(a, 22), maj = (a & b) ^ (a & c) ^ (b & c), t2 = (S0 + maj) >>> 0;
			h0 = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
		}
		for (let j = 0; j < 8; j++)h[j] = (h[j] + (j === 0 ? a : j === 1 ? b : j === 2 ? c : j === 3 ? d : j === 4 ? e : j === 5 ? f : j === 6 ? g : h0)) >>> 0;
	}
	let hex = '';
	for (let i = 0; i < 7; i++) {
		for (let j = 24; j >= 0; j -= 8)hex += ((h[i] >>> j) & 0xFF).toString(16).padStart(2, '0');
	}
	return hex;
}

async function resolveAddrPort(proxyIP, targetDomain = 'dash.cloudflare.com', UUID = '00000000-0000-4000-8000-000000000000') {
	proxyIP = proxyIP.toLowerCase();
	function parseHostPortString(str) {
		let address = str, port = 443;
		if (str.includes(']:')) {
			const parts = str.split(']:');
			address = parts[0] + ']';
			port = parseInt(parts[1], 10) || port;
		} else if ((str.match(/:/g) || []).length === 1 && !str.startsWith('[')) {
			const colonIndex = str.lastIndexOf(':');
			address = str.slice(0, colonIndex);
			port = parseInt(str.slice(colonIndex + 1), 10) || port;
		}
		return [address, port];
	}

	function parseTxtProxyRecords(txtData) {
		return txtData.flatMap(data => {
			if (data.startsWith('"') && data.endsWith('"')) data = data.slice(1, -1);
			return data.replace(/\\010/g, ',').replace(/\n/g, ',').split(',').map(s => s.trim()).filter(Boolean);
		}).map(prefix => parseHostPortString(prefix));
	}

	const proxyIPList = await ensureArray(proxyIP);
	let allProxyList = [];
	const ipv4Regex = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
	const ipv6Regex = /^\[?(?:[a-fA-F0-9]{0,4}:){1,7}[a-fA-F0-9]{0,4}\]?$/;

	// 遍历数组中的每个IP元素进行处理
	for (const singleProxyIP of proxyIPList) {
		let [address, port] = parseHostPortString(singleProxyIP);

		if (singleProxyIP.includes('.tp')) {
			const tpMatch = singleProxyIP.match(/\.tp(\d+)/);
			if (tpMatch) port = parseInt(tpMatch[1], 10);
		}

		// 判断是否是域名（非IP地址）
		if (ipv4Regex.test(address) || ipv6Regex.test(address)) {
			log(`[反代解析] ${address} 为IP地址，直接使用`);
			allProxyList.push([address, port]);
			continue;
		}

		const [txtRecords, aRecords] = await Promise.all([
			dohQuery(address, 'TXT'),
			dohQuery(address, 'A')
		]);

		const txtData = txtRecords.filter(r => r.type === 16).map(r => (r.data));
		const txtAddresses = parseTxtProxyRecords(txtData);
		if (txtAddresses.length > 0) {
			log(`[反代解析] ${address} 使用TXT记录，共${txtAddresses.length}个结果`);
			allProxyList.push(...txtAddresses);
			continue;
		}

		const ipv4List = aRecords.filter(r => r.type === 1).map(r => r.data);
		if (ipv4List.length > 0) {
			log(`[反代解析] ${address} 未获取到TXT记录，使用A记录，共${ipv4List.length}个结果`);
			allProxyList.push(...ipv4List.map(ip => [ip, port]));
			continue;
		}

		const aaaaRecords = await dohQuery(address, 'AAAA');
		const ipv6List = aaaaRecords.filter(r => r.type === 28).map(r => `[${r.data}]`);
		if (ipv6List.length > 0) {
			log(`[反代解析] ${address} 未获取到TXT和A记录，使用AAAA记录，共${ipv6List.length}个结果`);
			allProxyList.push(...ipv6List.map(ip => [ip, port]));
		} else {
			log(`[反代解析] ${address} 未获取到TXT、A和AAAA记录，保留原域名`);
			allProxyList.push([address, port]);
		}
	}
	const sortedArray = allProxyList.sort((a, b) => a[0].localeCompare(b[0]));
	const targetRootDomain = targetDomain.includes('.') ? targetDomain.split('.').slice(-2).join('.') : targetDomain;
	let randomSeed = [...(targetRootDomain + UUID)].reduce((a, c) => a + c.charCodeAt(0), 0);
	log(`[反代解析] 随机种子: ${randomSeed}\n目标站点: ${targetRootDomain}`)
	const shuffled = [...sortedArray].sort(() => (randomSeed = (randomSeed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff - 0.5);
	const parseResult = shuffled.slice(0, 8);
	log(`[反代解析] 解析完成 总数: ${parseResult.length}个\n${parseResult.map(([ip, port], index) => `${index + 1}. ${ip}:${port}`).join('\n')}`);
	return parseResult;
}

//////////////////////////////////////////////////////HTML 伪装页（nginx / 1101 兜底）///////////////////////////////////////////////
async function nginx() {
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
	`
}

async function html1101(host, clientIP) {
	const now = new Date();
	const formatTimestamp = now.getFullYear() + '-' + String(now.getMonth() + 1).padStart(2, '0') + '-' + String(now.getDate()).padStart(2, '0') + ' ' + String(now.getHours()).padStart(2, '0') + ':' + String(now.getMinutes()).padStart(2, '0') + ':' + String(now.getSeconds()).padStart(2, '0');
	const randomString = Array.from(crypto.getRandomValues(new Uint8Array(8))).map(b => b.toString(16).padStart(2, '0')).join('');

	return `<!DOCTYPE html>
<!--[if lt IE 7]> <html class="no-js ie6 oldie" lang="en-US"> <![endif]-->
<!--[if IE 7]>    <html class="no-js ie7 oldie" lang="en-US"> <![endif]-->
<!--[if IE 8]>    <html class="no-js ie8 oldie" lang="en-US"> <![endif]-->
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
    <script>(function(){function d(){var b=a.getElementById("cf-footer-item-ip"),c=a.getElementById("cf-footer-ip-reveal");b&&"classList"in b&&(b.classList.remove("hidden"),c.addEventListener("click",function(){c.classList.add("hidden");a.getElementById("cf-footer-ip").classList.remove("hidden")}))}var a=document;document.addEventListener&&a.addEventListener("DOMContentLoaded",d)})();</script>
  </div><!-- /.error-footer -->

        </div><!-- /#cf-error-details -->
    </div><!-- /#cf-wrapper -->

     <script>
    window._cf_translation = {};


  </script>
</body>
</html>`;
}
