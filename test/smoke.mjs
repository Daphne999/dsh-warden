/**
 * smoke.mjs —— 不装进 DSH 也能验证插件挂载与工具行为。
 *
 * 用一个假的 cordis ctx 调用 apply()，截获 tools.register 拿到的工具定义，
 * 再直接 execute 一次，验证：注册成功、路径解析、市场交叉核对、报告渲染。
 *
 * 用法：node test/smoke.mjs [目标包名]
 */
import path from 'node:path';
import { apply } from '../lib/index.js';

const PROFILE = 'C:/Users/Isabella/.dsh/profiles/desktop';
const target = process.argv[2] || 'dsh-meme';

const registered = [];
const fakeCtx = {
  logger: { info: () => {}, debug: () => {}, warn: () => {} },
  get: (key) => (key === 'tools' ? { register: (def) => registered.push(def) } : undefined),
  effect: () => {},
  on: () => {},
  agents: undefined,
};

await apply(fakeCtx, { profileDir: PROFILE, marketPort: 61310 });

if (registered.length === 0) {
  console.error('❌ 没有注册任何工具');
  process.exit(1);
}

const tool = registered.find((t) => t.name === 'warden_audit');
if (!tool) {
  console.error('❌ 没找到 warden_audit，注册了:', registered.map((t) => t.name).join(', '));
  process.exit(1);
}
console.log('✅ 工具已注册:', tool.name);

try {
  const out = await tool.execute({ target });
  console.log('\n--- 报告 ---');
  console.log(out.report);
  console.log('\nverdict:', out.verdict, '| score:', out.score);
  if (typeof out.score !== 'number' || !out.verdict) {
    console.error('❌ 返回结构不完整');
    process.exit(1);
  }
} catch (err) {
  console.error('❌ execute 失败:', err.message);
  process.exit(1);
}

// 非法目标应报错而不是崩
try {
  await tool.execute({ target: 'definitely-not-installed-xyz' });
  console.error('❌ 不存在的目标没有报错');
  process.exit(1);
} catch {
  console.log('\n✅ 不存在的目标正确报错');
}
