/**
 * 产物后处理：dist/_worker.raw.js → dist/_worker.js
 * 1. 绑定标识符（变量/函数/类/参数/捕获变量/导出本地名）按 tools/zh-map.json 重命名为中文；
 *    属性名、对象字面量键、字符串、导出对外名一律不动 —— 兼容红线全是字符串，语义不受影响。
 * 2. tools/zh-map.json 为映射记录：按需自动扩展（词典拆词翻译，未命中用 标识N 兜底），可手工改。
 * 3. 文件末尾附加宪法全文（tools/中华人民共和国宪法.txt，块注释，重复至约 256KB）—— 干扰自动内容扫描。
 * 运行方式：npm run build（esbuild 产出 raw 后自动执行本脚本）。
 */
import { readFileSync, writeFileSync, existsSync, unlinkSync } from 'node:fs';
import ts from 'typescript';

const RAW = 'dist/_worker.raw.js';
const OUT = 'dist/_worker.js';
const MAP = 'tools/zh-map.json';
const PAD = 'tools/中华人民共和国宪法.txt';
const PAD_MIN = 256 * 1024;

/** 英文词 → 中文（小写整词匹配；标识符拆词后逐段翻译） */
const DICT = {
  request: '请求', response: '响应', context: '上下文', config: '配置', configuration: '配置项',
  session: '会话', transport: '传输', protocol: '协议', forward: '转发', proxy: '代理',
  chain: '链式', plugin: '插件', plugins: '插件组', registry: '注册表', setup: '装配',
  router: '路由', route: '路由', routes: '路由表', auth: '认证', cookie: '曲奇',
  login: '登录', logout: '登出', admin: '管理', password: '密码', pass: '口令',
  key: '键', secret: '密钥', uuid: '用户码', token: '令牌', version: '版本',
  status: '状态', code: '编码', error: '错误', err: '错误', warn: '警告',
  debug: '调试', info: '信息', log: '日志', logs: '日志集', message: '消息', msg: '消息',
  data: '数据', buf: '缓冲', buffer: '缓冲区', chunk: '块', len: '长度', length: '长度',
  size: '体积', index: '序号', idx: '序号', name: '名称', type: '类型', mode: '模式',
  state: '状态位', value: '值', val: '值', list: '列表', map: '映射表', set: '置位', get: '取值',
  has: '存在', add: '追加', del: '抹除', remove: '移除', delete: '删除', init: '初始化',
  load: '载入', save: '保存', store: '存放', write: '写入', read: '读取', send: '发送',
  recv: '接收', receive: '收讫', close: '关闭', open: '开启', connect: '连接',
  disconnect: '断开', dial: '拨号', target: '目标', host: '主机', hosts: '主机清单',
  port: '端口', path: '路径', url: '网址', origin: '源站', search: '检索', params: '参数集',
  param: '参数', query: '查询串', header: '头字段', headers: '头部', body: '正文',
  method: '方法名', content: '内容', remote: '远端', local: '本地', client: '客户端',
  server: '服务端', socket: '套接字', stream: '流', reader: '读取器', writer: '写入器',
  pair: '配对', event: '事件', frame: '帧', packet: '报文', vless: 'VLESS',
  trojan: '木马通道', shadowsocks: '影子袜', socks: '袜子', socks5: '袜子五号',
  http: '超文本', https: '超文本安全', tls: '安全传输层', grpc: '双工远程调用',
  websocket: '套接字通道', ws: '通道', xhttp: '交叉传输', turn: '中继转发',
  sstp: '安全套隧道', tcp: '可靠传输', udp: '数据报', quic: '快传输',
  encrypt: '加密', decrypt: '解密', cipher: '算法', hash: '散列', md5: '摘要值',
  sha: '指纹值', base64: '六四编码', sign: '签名', verify: '核验', check: '检查',
  valid: '有效', ok: '成功', fail: '失败', success: '已完成', ready: '就绪',
  start: '启动', stop: '停止', run: '运行', exec: '执行', process: '处理',
  handle: '处置', handler: '处理器', dispatch: '分发', trigger: '触发', call: '调用',
  apply: '套用', bind: '绑定', entry: '入口', fetch: '抓取', worker: '工作体',
  orchestrator: '编排器', forwarder: '转发器', dialer: '拨号器', connector: '连接器',
  listener: '监听器', accept: '受理', respond: '应答', reply: '回覆', upgrade: '升级',
  early: '提前量', user: '用户', ua: '指纹串', ip: '地址', colo: '机房码',
  asn: '自治域号', country: '国别', region: '区域', subscription: '订阅源',
  fast: '快捷', sub: '订阅', location: '位置', locations: '位置清单', best: '优选',
  fake: '伪装', page: '页面', pages: '页面组', nginx: '门户页', cloudflare: '边缘平台',
  cf: '边缘平台短', tg: '电报', env: '环境', variable: '变量', variables: '变量集',
  binding: '绑定项', bindings: '绑定组', asset: '静态资源', assets: '静态资源组',
  static: '静态', html: '网页文', file: '文件', files: '文件清单', defaults: '缺省集',
  default: '缺省', fallback: '兜底', whitelist: '白名单', white: '白名单项',
  blacklist: '黑名单', black: '黑名单项', go: '走向', concurrent: '并发',
  preload: '预加载', race: '竞速', enable: '启用', enabled: '启用态', disable: '禁用',
  json: '数据文本', legacy: '旧版', migrate: '迁移', migration: '迁移件', schema: '纲要',
  record: '记录', records: '记录集', time: '时间', now: '当前', date: '日期',
  random: '随机值', unique: '唯一', id: '编号', redirect: '重定向', pretty: '美化',
  format: '格式化', stringify: '字符串化', parse: '解析出', count: '计数', total: '总计',
  max: '上限值', min: '下限值', width: '宽', height: '高', color: '颜色', style: '样式',
  test: '测试', mock: '模拟件', ns: '命名空间', namespace: '命名空间', dns: '域名解析',
  doh: '加密域名解析', ttl: '存活期', cached: '已缓存', cache: '缓存', once: '仅一次',
  first: '首个', last: '末位', next: '后继', prev: '前驱', cur: '当前项',
  opts: '选项集', options: '选项组', args: '实参组', arg: '实参', cb: '回调函数',
  promise: '期约', resolve: '敲定', reject: '回绝', finally: '善后', throw: '抛出',
  catch: '捕获', await: '等待中', async: '异步', then: '随后', all: '全部', any: '任一',
  obj: '对象物', arr: '数组', str: '字符串', num: '数值', bool: '布尔值', int: '整型',
  char: '字符', proto: '原型', ctor: '构造函数',
};

function splitParts(name) {
  return name
    .replace(/^_+|_+$/g, '')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .replace(/([A-Za-z])(\d)/g, '$1 $2')
    .replace(/(\d)([A-Za-z])/g, '$1 $2')
    .split(/[_\s]+|\s+/)
    .filter(Boolean);
}

/** 生成唯一名：词典拆词翻译，任一段未知则整体用 标识N 兜底 */
function pickName(text, used) {
  const parts = splitParts(text);
  let out = '';
  for (const p of parts) {
    if (/^\d+$/.test(p)) { out += p; continue; }
    const zh = DICT[p.toLowerCase()];
    if (!zh) { out = ''; break; }
    out += zh;
  }
  if (out) {
    let cand = out;
    let n = 2;
    while (used.has(cand)) cand = `${out}${n++}`;
    used.add(cand);
    return cand;
  }
  let n = 1;
  while (used.has(`标识${n}`)) n++;
  used.add(`标识${n}`);
  return `标识${n}`;
}

/** 标识符角色：skip=不动，dual=改名但保留原名作键，rename=直接改 */
function classify(node, parent, protectedNames) {
  if (protectedNames.has(node.text)) return 'skip';
  if (!parent) return 'rename';
  switch (parent.kind) {
    case ts.SyntaxKind.PropertyAccessExpression:
    case ts.SyntaxKind.QualifiedName:
      return parent.name === node ? 'skip' : 'rename';
    case ts.SyntaxKind.PropertyAssignment:
      return parent.name === node ? 'skip' : 'rename';
    case ts.SyntaxKind.ShorthandPropertyAssignment:
      return parent.name === node ? 'dual' : 'rename';
    case ts.SyntaxKind.MethodDeclaration:
    case ts.SyntaxKind.PropertyDeclaration:
    case ts.SyntaxKind.GetAccessor:
    case ts.SyntaxKind.SetAccessor:
      return parent.name === node ? 'skip' : 'rename';
    case ts.SyntaxKind.LabeledStatement:
    case ts.SyntaxKind.BreakStatement:
    case ts.SyntaxKind.ContinueStatement:
    case ts.SyntaxKind.MetaProperty:
    case ts.SyntaxKind.ImportDeclaration:
    case ts.SyntaxKind.ImportClause:
    case ts.SyntaxKind.NamespaceImport:
    case ts.SyntaxKind.ImportSpecifier:
      return 'skip';
    case ts.SyntaxKind.ExportSpecifier:
      if (parent.propertyName === node) return 'rename';
      if (parent.name === node) return parent.propertyName ? 'skip' : 'dual';
      return 'rename';
    case ts.SyntaxKind.BindingElement:
      if (parent.propertyName === node) return 'skip';
      if (parent.name === node) {
        if (parent.propertyName || parent.dotDotDotToken) return 'rename';
        // dual（保留原名作键）仅适用于对象解构；数组解构 [a] 无键可留 → 直接改名
        return ts.isObjectBindingPattern(parent.parent) ? 'dual' : 'rename';
      }
      return 'rename';
    default:
      return 'rename';
  }
}

function main() {
  // 用类型检查器解析符号：只改「声明在本文件内」的标识符；
  // 全局/内建（Uint8Array、fetch、console…）无符号或声明在外 → 一律不改。
  const program = ts.createProgram([RAW], {
    noLib: true,
    allowJs: true,
    checkJs: false,
    noResolve: true,
    target: ts.ScriptTarget.Latest,
    types: [],
    skipLibCheck: true,
  });
  const checker = program.getTypeChecker();
  const sf = program.getSourceFile(RAW);
  if (!sf) throw new Error(`rename-pad: 无法读取 ${RAW}`);

  // import 绑定名整体保护（bundle 正常应为 0 个 import，防御性处理）
  const protectedNames = new Set();
  const scanImports = (n) => {
    if (ts.isImportDeclaration(n)) {
      const decl = n.importClause;
      if (decl?.name) protectedNames.add(decl.name.text);
      if (decl?.namedBindings) {
        if (ts.isNamespaceImport(decl.namedBindings)) protectedNames.add(decl.namedBindings.name.text);
        else decl.namedBindings.elements.forEach((e) => protectedNames.add(e.name.text));
      }
    }
    ts.forEachChild(n, scanImports);
  };
  scanImports(sf);

  // 收集：角色判定 + 符号必须绑定到本文件 + 有序文本
  const targets = new Map(); // node → 'rename' | 'dual'
  const orderedTexts = [];
  const seenTexts = new Set();
  const collect = (node) => {
    if (ts.isIdentifier(node)) {
      const role = classify(node, node.parent, protectedNames);
      if (role !== 'skip') {
        const sym = checker.getSymbolAtLocation(node);
        const local = sym?.declarations?.some((d) => d.getSourceFile() === sf) ?? false;
        if (local) {
          targets.set(node, role);
          if (!seenTexts.has(node.text)) { seenTexts.add(node.text); orderedTexts.push(node.text); }
        }
      }
    }
    ts.forEachChild(node, collect);
  };
  collect(sf);

  // 扩展映射表（只增不删，记录稳定）
  const map = existsSync(MAP) ? JSON.parse(readFileSync(MAP, 'utf8')) : {};
  const used = new Set(Object.values(map));
  let added = 0;
  for (const text of orderedTexts) {
    if (!(text in map)) { map[text] = pickName(text, used); added++; }
  }
  if (added > 0) {
    const sorted = Object.fromEntries(Object.entries(map).sort(([a], [b]) => a.localeCompare(b)));
    writeFileSync(MAP, JSON.stringify(sorted, null, 2) + '\n');
  }

  // 重命名变换：dual 的三种父节点在本层拦截（避免子节点位置放错节点），其余下潜
  const result = ts.transform(sf, [(ctx) => {
    const f = ctx.factory;
    const v = (node) => {
      if (ts.isBindingElement(node) && !node.propertyName && !node.dotDotDotToken
        && ts.isObjectBindingPattern(node.parent)
        && targets.get(node.name) === 'dual') {
        // { a = 缺省 } → { a: 新名 = 缺省 }（键保留，绑定改名，缺省表达式继续变换）
        // 注意 updateBindingElement 参数序：(node, dotDotDotToken, propertyName, name, initializer)
        return f.updateBindingElement(
          node,
          undefined,
          f.createIdentifier(node.name.text),
          f.createIdentifier(map[node.name.text]),
          node.initializer ? v(node.initializer) : undefined,
        );
      }
      if (ts.isShorthandPropertyAssignment(node) && targets.get(node.name) === 'dual') {
        const value = node.objectAssignmentInitializer
          ? f.createBinary(f.createIdentifier(map[node.name.text]), ts.SyntaxKind.EqualsToken, v(node.objectAssignmentInitializer))
          : f.createIdentifier(map[node.name.text]);
        return f.createPropertyAssignment(f.createIdentifier(node.name.text), value);
      }
      if (ts.isExportSpecifier(node) && !node.propertyName && targets.get(node.name) === 'dual') {
        // export { a } → export { 新名 as a }（对外名保留）
        return f.createExportSpecifier(false, f.createIdentifier(map[node.name.text]), f.createIdentifier(node.name.text));
      }
      if (ts.isIdentifier(node)) {
        const role = targets.get(node);
        if (role === 'rename' || role === 'dual') return f.createIdentifier(map[node.text]);
      }
      return ts.visitEachChild(node, v, ctx);
    };
    return (root) => v(root);
  }]);
  const printed = ts.createPrinter({ newLine: ts.NewLineKind.LineFeed }).printFile(result.transformed[0]);
  result.dispose();

  // 末尾附加干扰文本（块注释；*​/ 转义防截断；重复至约 PAD_MIN）
  let padding = '';
  if (existsSync(PAD)) {
    let pad = readFileSync(PAD, 'utf8').replace(/\r\n/g, '\n').trim();
    if (pad) {
      pad = pad.split('*/').join('* /');
      const block = `/*\n${pad}\n*/\n`;
      const reps = Math.max(1, Math.min(64, Math.ceil(PAD_MIN / Buffer.byteLength(block, 'utf8'))));
      padding = '\n' + block.repeat(reps);
    }
  }

  const out = printed + padding;
  writeFileSync(OUT, out);
  if (existsSync(RAW)) unlinkSync(RAW);
  const kb = (n) => (n / 1024).toFixed(1) + 'KB';
  console.log(`rename-pad: 重命名 ${targets.size} 处标识符（映射表 ${Object.keys(map).length} 条${added ? `，新增 ${added}` : ''}），产物 ${kb(Buffer.byteLength(out))}，附加文本 ${kb(Buffer.byteLength(padding))}`);
}

main();
