/**
 * audit.js —— 插件安全体检的核心逻辑（纯函数式，不依赖 DSH API，便于单测）。
 *
 * 检查项：
 *   1. 安装期脚本（preinstall / install / postinstall / prepare）—— 会在装包时执行
 *   2. 原生模块依赖（需要编译或下载二进制）
 *   3. 源码里的外联域名
 *   4. 源码里的高危 API（child_process / eval / vm / 动态 Function …）
 *   5. 凭据相关路径（.ssh / .env / credentials）
 *   6. manifest 声明是否完整（dsh.bundle / dsh.client）
 *   7. 与市场注册表交叉核对：capabilities / redLines / star / 下载量
 *
 * 输出一个 { score, verdict, findings[] } 结构；不修改任何文件，不执行被审计代码。
 */
import fs from 'node:fs';
import path from 'node:path';

const INSTALL_HOOKS = ['preinstall', 'install', 'postinstall', 'prepare'];
const NATIVE_DEPS = /(sharp|onnxruntime|node-gyp|node-pre-gyp|sqlite3|better-sqlite3|bcrypt|canvas|node-sass|sass-embedded|esbuild|@swc\/core|puppeteer|playwright)/i;
const DANGEROUS = [
  ['child_process', /(?:require\(['"]child_process|from ['"]node:child_process|from ['"]child_process)/],
  ['execSync / spawnSync', /\b(execSync|spawnSync|execFileSync)\s*\(/],
  ['eval', /\beval\s*\(/],
  ['new Function', /new\s+Function\s*\(/],
  ['vm 模块', /from ['"](?:node:)?vm['"]|require\(['"](?:node:)?vm['"]\)/],
  ['递归删除', /\b(rmSync|rmdirSync|unlinkSync)\s*\(/],
  ['写启动项/注册表', /(CurrentVersion\\\\Run|schtasks|reg\s+add)/i],
];
const CRED_HINTS = [
  ['~/.ssh', /(\.ssh[\\/])/],
  ['一个 .env 文件路径', /['"][^'"\n]{0,80}\.env(?:\.(?:local|production|development))?['"]|[\\/]\.env\b/],
  ['credentials.yaml', /(credentials\.ya?ml)/],
  ['~/.aws', /(\.aws[\\/])/],
  ['.npmrc', /(\.npmrc)/],
  ['.git-credentials', /(\.git-credentials)/],
];
const SCAN_DIRS = ['lib', 'dist', 'src', 'client', 'assets/scripts', 'scripts'];
const MAX_FILES = 400;
const MAX_BYTES = 2 * 1024 * 1024;
const SCAN_EXT = new Set(['.js', '.mjs', '.cjs', '.ts', '.json', '.yml', '.yaml', '.sh', '.ps1', '.cmd', '.bat']);

const readJson = (file) => {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
};

function walk(dir, out = [], budget = { left: MAX_FILES }) {
  if (budget.left <= 0) return out;
  let entries = [];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    if (budget.left <= 0) break;
    if (e.name === 'node_modules' || e.name === '.git') continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      walk(full, out, budget);
      continue;
    }
    const ext = path.extname(e.name).toLowerCase();
    if (!SCAN_EXT.has(ext)) continue;
    try {
      const st = fs.statSync(full);
      if (st.size > MAX_BYTES) continue;
      out.push(full);
      budget.left -= 1;
    } catch {
      /* ignore */
    }
  }
  return out;
}

function scanSource(root) {
  const files = [];
  for (const d of SCAN_DIRS) {
    const full = path.join(root, d);
    if (fs.existsSync(full)) walk(full, files);
  }
  if (files.length === 0) walk(root, files);

  const hosts = new Map();
  const hits = new Map();
  const creds = new Map();

  for (const file of files) {
    let text = '';
    try {
      text = fs.readFileSync(file, 'utf8');
    } catch {
      continue;
    }
    const rel = path.relative(root, file);
    // 自扫描豁免：warden 自己的规则表里就写着 child_process / eval 这些字面量，
    // 扫自己必然全中。只对这个插件、且只对"危险 API"这一项豁免。
    const definesPatterns = /const DANGEROUS = \[/.test(text) || /DANGEROU[S]_?API/i.test(text);
    const isSelfRules = definesPatterns && /(^|[\\/])audit\.js$/.test(file);
    for (const m of text.matchAll(/https?:\/\/([a-zA-Z0-9._-]+)/g)) {
      const host = m[1].toLowerCase();
      if (!hosts.has(host)) hosts.set(host, new Set());
      hosts.get(host).add(rel);
    }
    if (!isSelfRules) {
      for (const [label, re] of DANGEROUS) {
        if (re.test(text)) {
          if (!hits.has(label)) hits.set(label, new Set());
          hits.get(label).add(rel);
        }
      }
      // 规则表里同样写着 .ssh / .env 这些字面量，自扫描时一并豁免
      for (const [label, re] of CRED_HINTS) {
        if (re.test(text)) {
          if (!creds.has(label)) creds.set(label, new Set());
          creds.get(label).add(rel);
        }
      }
    }
  }
  return { files: files.length, hosts, hits, creds, selfExempt: files.some((f) => /(^|[\\/])audit\.js$/.test(f)) };
}

/**
 * 审计一个插件目录。
 * @param {string} root 插件根目录（含 package.json）
 * @param {object} [marketEntry] 市场注册表里的对应条目（可选）
 */
export function auditPlugin(root, marketEntry) {
  const findings = [];
  const add = (level, code, message) => findings.push({ level, code, message });

  const pkgFile = path.join(root, 'package.json');
  if (!fs.existsSync(pkgFile)) {
    return { ok: false, score: 0, verdict: 'unknown', findings: [{ level: 'error', code: 'no-package', message: '目录里没有 package.json' }] };
  }
  const pkg = readJson(pkgFile) || {};

  // 1. manifest
  const hasBundle = !!(pkg.dsh && pkg.dsh.bundle && pkg.dsh.bundle.patch);
  const hasClient = !!(pkg.dsh && pkg.dsh.client);
  if (!hasBundle && hasClient) add('high', 'client-only', '只声明了 dsh.client，没有 dsh.bundle —— 这种装不上（市场也会拒收）');
  if (!hasBundle && !hasClient) add('medium', 'no-manifest', 'package.json 里没有 dsh 元数据，可能不是 DSH 插件');

  // 2. 安装期脚本
  const scripts = pkg.scripts || {};
  for (const hook of INSTALL_HOOKS) {
    if (scripts[hook]) add('high', 'install-hook', `声明了 ${hook} 脚本，安装时会执行：${String(scripts[hook]).slice(0, 120)}`);
  }

  // 3. 原生依赖
  const deps = { ...(pkg.dependencies || {}), ...(pkg.optionalDependencies || {}) };
  const natives = Object.keys(deps).filter((d) => NATIVE_DEPS.test(d));
  if (natives.length) add('medium', 'native-deps', `依赖原生模块（可能触发编译/下载二进制）：${natives.join(', ')}`);

  // 4/5. 源码扫描
  const src = scanSource(root);
  if (src.hits.size) {
    for (const [label, files] of src.hits) {
      // child_process 对很多正经插件是必需品（浏览器驱动、终端类），单独出现只算中等；
      // eval / new Function / 写启动项才是真正的高危信号
      const level = ['eval', 'new Function', '写启动项/注册表'].includes(label) ? 'high' : 'medium';
      add(level, 'dangerous-api', `源码用到「${label}」：${[...files].slice(0, 3).join(', ')}`);
    }
  }
  const exoticHosts = [...src.hosts.keys()].filter((h) => !/(github\.com|githubusercontent\.com|npmjs\.org|deepseek\.com|localhost|127\.0\.0\.1)/.test(h));
  if (exoticHosts.length) add('info', 'egress', `会连接 ${exoticHosts.length} 个外部域名：${exoticHosts.slice(0, 12).join(', ')}`);
  if (src.creds.size) {
    for (const [label, files] of src.creds) add('high', 'credential-path', `源码出现凭据相关路径「${label}」：${[...files].slice(0, 2).join(', ')}`);
  }

  // 6. 市场交叉核对
  if (marketEntry) {
    const caps = marketEntry.capabilities || [];
    if (caps.includes('shell')) add('medium', 'cap-shell', '市场标注它拥有 shell 执行能力');
    if (caps.includes('credentials')) add('high', 'cap-credentials', '市场标注它会读取凭据/密钥');
    if ((marketEntry.capabilityRedLines || []).length) add('high', 'red-line', `市场红线：${(marketEntry.capabilityRedLines || []).join('; ')}`);
    if (typeof marketEntry.stars === 'number' && marketEntry.stars < 50) add('info', 'low-stars', `仓库只有 ${marketEntry.stars} star，样本太少`);
    if (!marketEntry.npm) add('info', 'git-only', '这个插件没有发布到 npm（走 git 安装），来源需自行核对');
  } else {
    add('info', 'not-in-market', '市场注册表里没有这个插件，来源无法交叉验证');
  }

  // 打分
  const weight = { high: 18, medium: 8, info: 2, error: 40 };
  let score = 100;
  for (const f of findings) score -= weight[f.level] ?? 5;
  score = Math.max(0, Math.min(100, score));
  const verdict = score >= 75 ? 'safe' : score >= 50 ? 'caution' : 'risky';

  return { ok: true, name: pkg.name, version: pkg.version, license: pkg.license || null, score, verdict, files: src.files, hosts: [...src.hosts.keys()], findings };
}

/** 把报告渲染成给人看的短文本 */
export function renderReport(r) {
  const icon = r.verdict === 'safe' ? '✅' : r.verdict === 'caution' ? '⚠️' : '🛑';
  const lines = [`${icon} ${r.name || '?'} v${r.version || '?'} —— 评分 ${r.score}/100（${r.verdict}）`];
  if (r.license) lines.push(`license: ${r.license} | 扫描文件 ${r.files} 个`);
  const order = { high: 0, medium: 1, info: 2, error: -1 };
  for (const f of [...r.findings].sort((a, b) => (order[a.level] ?? 9) - (order[b.level] ?? 9))) {
    const tag = f.level === 'high' ? '🔴' : f.level === 'medium' ? '🟠' : f.level === 'error' ? '⛔' : 'ℹ️';
    lines.push(`${tag} ${f.message}`);
  }
  if (r.findings.length === 0) lines.push('没发现明显问题。');
  return lines.join('\n');
}
