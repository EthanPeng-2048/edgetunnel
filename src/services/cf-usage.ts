/**
 * Cloudflare 用量查询（原 getCloudflareUsage，行为等价移植）。
 * loadConfig 的 CF 段在 cf.json 存在且带凭据时调用；网络失败返回全零结构。
 */
export interface CfUsageResult {
  success: boolean;
  pages: number;
  workers: number;
  total: number;
  max: number;
}

const CF_API = 'https://api.cloudflare.com/client/v4';

export async function getCloudflareUsage(
  Email: string | null,
  GlobalAPIKey: string | null,
  AccountID: string | null,
  APIToken: string | null,
): Promise<CfUsageResult> {
  const sum = (a: Array<{ sum?: { requests?: number } }> | undefined): number =>
    a?.reduce((t, i) => t + (i?.sum?.requests || 0), 0) || 0;
  const cfg = { 'Content-Type': 'application/json' };

  try {
    if (!AccountID && (!Email || !GlobalAPIKey)) return { success: false, pages: 0, workers: 0, total: 0, max: 100000 };

    if (!AccountID) {
      const r = await fetch(`${CF_API}/accounts`, {
        method: 'GET',
        headers: { ...cfg, 'X-AUTH-EMAIL': Email!, 'X-AUTH-KEY': GlobalAPIKey! },
      });
      if (!r.ok) throw new Error(`账户获取失败: ${r.status}`);
      const d = (await r.json()) as { result?: Array<{ name?: string; id?: string }> };
      if (!d?.result?.length) throw new Error('未找到账户');
      const idx = d.result.findIndex((a) => a.name?.toLowerCase().startsWith(Email!.toLowerCase()));
      AccountID = d.result[idx >= 0 ? idx : 0]?.id ?? null;
    }

    const now = new Date();
    now.setUTCHours(0, 0, 0, 0);
    const hdr = APIToken
      ? { ...cfg, Authorization: `Bearer ${APIToken}` }
      : { ...cfg, 'X-AUTH-EMAIL': Email!, 'X-AUTH-KEY': GlobalAPIKey! };

    const res = await fetch(`${CF_API}/graphql`, {
      method: 'POST',
      headers: hdr,
      body: JSON.stringify({
        query: `query getBillingMetrics($AccountID: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) {
					viewer { accounts(filter: {accountTag: $AccountID}) {
						pagesFunctionsInvocationsAdaptiveGroups(limit: 1000, filter: $filter) { sum { requests } }
						workersInvocationsAdaptive(limit: 10000, filter: $filter) { sum { requests } }
					} }
				}`,
        variables: { AccountID, filter: { datetime_geq: now.toISOString(), datetime_leq: new Date().toISOString() } },
      }),
    });

    if (!res.ok) throw new Error(`查询失败: ${res.status}`);
    const result = (await res.json()) as {
      errors?: Array<{ message: string }>;
      data?: { viewer?: { accounts?: Array<{ pagesFunctionsInvocationsAdaptiveGroups?: unknown; workersInvocationsAdaptive?: unknown }> } };
    };
    if (result.errors?.length) throw new Error(result.errors[0]!.message);

    const acc = result?.data?.viewer?.accounts?.[0];
    if (!acc) throw new Error('未找到账户数据');

    const pages = sum(acc.pagesFunctionsInvocationsAdaptiveGroups as Array<{ sum?: { requests?: number } }> | undefined);
    const workers = sum(acc.workersInvocationsAdaptive as Array<{ sum?: { requests?: number } }> | undefined);
    const total = pages + workers;
    const max = 100000;
    console.log(`统计结果 - Pages: ${pages}, Workers: ${workers}, 总计: ${total}, 上限: 100000`);
    return { success: true, pages, workers, total, max };
  } catch (error) {
    console.error('获取使用量错误:', (error as Error).message);
    return { success: false, pages: 0, workers: 0, total: 0, max: 100000 };
  }
}
