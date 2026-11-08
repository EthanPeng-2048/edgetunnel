/**
 * Registry / pickBest 测试（DESIGN.md §4.6）。
 */
import { describe, expect, it } from 'vitest';
import { Registry, pickBest } from '../src/registry';
import { TunnelError } from '../src/errors';

interface FakeComponent {
  readonly name: string;
  readonly weight?: number;
}

describe('Registry', () => {
  it('注册后可按名查找', () => {
    const reg = new Registry<FakeComponent>();
    reg.register({ name: 'ws' }).register({ name: 'grpc' });
    expect(reg.get('ws')?.name).toBe('ws');
    expect(reg.get('grpc')?.name).toBe('grpc');
    expect(reg.size).toBe(2);
  });

  it('未注册返回 undefined', () => {
    const reg = new Registry<FakeComponent>();
    expect(reg.get('nope')).toBeUndefined();
  });

  it('重名注册抛 REGISTRY_DUPLICATE', () => {
    const reg = new Registry<FakeComponent>();
    reg.register({ name: 'ws' });
    expect(() => reg.register({ name: 'ws' })).toThrow(TunnelError);
    try {
      reg.register({ name: 'ws' });
    } catch (err) {
      expect((err as TunnelError).code).toBe('REGISTRY_DUPLICATE');
    }
  });

  it('list 返回注册顺序副本', () => {
    const reg = new Registry<FakeComponent>();
    reg.register({ name: 'a' }).register({ name: 'b' }).register({ name: 'c' });
    expect(reg.list().map((c) => c.name)).toEqual(['a', 'b', 'c']);
  });
});

describe('pickBest（评分择优，同分先注册优先）', () => {
  const items: FakeComponent[] = [
    { name: 'low', weight: 1 },
    { name: 'high', weight: 10 },
    { name: 'tie', weight: 10 },
    { name: 'zero', weight: 0 },
  ];

  it('取最高分', () => {
    expect(pickBest(items, (i) => i.weight ?? 0)?.name).toBe('high');
  });

  const byName = (name: string) => (i: FakeComponent) => (i.name === name ? 1 : 0);

  it('同分保留先注册者', () => {
    expect(pickBest(items, byName('tie'))?.name).toBe('tie');
    const tieFirst: FakeComponent[] = [{ name: 't1', weight: 5 }, { name: 't2', weight: 5 }];
    expect(pickBest(tieFirst, () => 5)?.name).toBe('t1');
  });

  it('全 0 分返回 undefined', () => {
    expect(pickBest(items, () => 0)).toBeUndefined();
  });

  it('空列表返回 undefined', () => {
    expect(pickBest([], () => 1)).toBeUndefined();
  });

  it('负分不入选（0 分为下限）', () => {
    const negative: FakeComponent[] = [{ name: 'n', weight: -5 }];
    expect(pickBest(negative, (i) => i.weight ?? 0)).toBeUndefined();
  });
});
