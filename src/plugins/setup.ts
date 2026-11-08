/**
 * 插件注册（启动期一次，导入即注册 —— DESIGN.md §4.5「可插拔」）。
 *
 * 注册顺序即主路由链遍历顺序，与原 else-if 链等价性见各插件文件头：
 *   Subscription（fast-sub 先于 login）→ BestIp（getADDAPI/locations）
 *   → AdminUi（admin 子 API）→ FakePage（fallback，Router 单独调用）。
 * 新增插件 = 新 Plugin 子类 + 此处一行注册。
 */
import { registerPlugin } from './registry';
import { SubscriptionPlugin } from './subscription';
import { BestIpPlugin } from './best-ip';
import { AdminUiPlugin } from './admin-ui';
import { FakePagePlugin } from './fake-page';

let registered = false;

export function setupPlugins(): void {
  if (registered) return;
  registered = true;
  registerPlugin(new SubscriptionPlugin());
  registerPlugin(new BestIpPlugin());
  registerPlugin(new AdminUiPlugin());
  registerPlugin(new FakePagePlugin());
}

setupPlugins();
