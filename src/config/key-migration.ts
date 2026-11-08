/**
 * 配置键名迁移（原 _worker.js 章节 7：CONFIG_KEY_CN_TO_EN / CONFIG_KEY_EN_TO_CN）。
 *
 * 内部统一使用英文键；外部管理页（edt-pages）仍按历史中文键读写。
 * 兼容红线 #1：此层在管理页自制完成前不可移除。
 * 映射表逐字提取自 _worker.js（85 对，双向零冲突）。
 */

/** 中文键 → 英文键（读入 KV / 接收管理页 POST 时就地迁移） */
export const CONFIG_KEY_CN_TO_EN: Readonly<Record<string, string>> = {
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
}

/** 英文键 → 中文键（响应管理页 GET 时深拷贝后迁移回去） */
export const CONFIG_KEY_EN_TO_CN: Readonly<Record<string, string>> = {
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
}

/**
 * 就地深度迁移对象键名（仅重命名 map 中出现的键，递归进入数组与嵌套对象）。
 * 与原实现逐行等价；改名后的键会追加到对象尾部（键序变化属预期，测试用键序无关比较）。
 */
export function migrateConfigKeysDeep<T>(value: T, map: Readonly<Record<string, string>>): T {
  if (!value || typeof value !== "object") return value;
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      value[i] = migrateConfigKeysDeep(value[i], map);
    }
    return value;
  }
  const obj = value as Record<string, unknown>;
  for (const key of Object.keys(obj)) {
    const mapped = map[key];
    if (mapped !== undefined && mapped !== key) {
      obj[mapped] = migrateConfigKeysDeep(obj[key], map);
      delete obj[key];
    } else {
      obj[key] = migrateConfigKeysDeep(obj[key], map);
    }
  }
  return value;
}

/**
 * 深拷贝并转回管理页使用的中文键。
 * 禁止就地修改：调用方持有的 config 可能被跨逻辑复用（原实现曾因此出 bug）。
 */
export function toLegacyConfig<T>(config: T): T {
  return migrateConfigKeysDeep(JSON.parse(JSON.stringify(config)), CONFIG_KEY_EN_TO_CN);
}
