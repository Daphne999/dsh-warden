/**
 * dsh-warden —— 装插件前的安全体检。
 *
 * 为什么需要：插件跑在宿主进程里，等于把 shell、文件、网络、凭据全交出去。
 * 外面那个 gating-hub 想接管下载链，反而放大风险；这里只做一件事——
 * **读代码、给结论，不执行、不代理、不改任何东西**。
 *
 * 暴露的工具：warden_audit
 *   target  包名（已安装）或绝对路径
 * 返回：评分 + 判定 + 逐条发现
 */
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { auditPlugin, renderReport } from './audit.js';

export const name = 'dsh-warden';
export const inject = ['tools'];

const defaultProfileDir = () => {
  // 宿主进程一般以 profile 目录或其子目录作为 cwd；两处都试
  const cwd = process.cwd();
  return fs.existsSync(path.join(cwd, 'package.json')) ? cwd : cwd;
};

export async function apply(ctx, config = {}) {
  const log = (line) => {
    try {
      ctx.logger?.info?.(`[dsh-warden] ${line}`);
    } catch {}
    try {
      console.log(`[dsh-warden] ${line}`);
    } catch {}
  };

  const profileDir = config.profileDir ? path.resolve(config.profileDir) : defaultProfileDir();
  // 宿主端口不固定（每次启动可能换），优先问 webServer 要真实端口
  const marketPort = (() => {
    if (config.marketPort) return Number(config.marketPort);
    try {
      const ws = ctx.get('webServer');
      const p = ws?.port ?? ws?.server?.address?.()?.port;
      if (p) return Number(p);
    } catch {}
    return Number(process.env.DSH_PORT || process.env.DSH_WEB_PORT || 61310);
  })();

  // ---------- 解析目标路径 ----------
  function resolveTarget(target) {
    if (!target) return null;
    if (path.isAbsolute(target) && fs.existsSync(path.join(target, 'package.json'))) return target;

    const candidates = [
      path.join(profileDir, 'node_modules', target),
      path.join(process.cwd(), 'node_modules', target),
    ];
    for (const c of candidates) {
      if (fs.existsSync(path.join(c, 'package.json'))) return c;
    }
    // 再试一次模块解析（处理 scoped 包与软链）
    try {
      const req = createRequire(path.join(profileDir, 'package.json'));
      const pkgFile = req.resolve(`${target}/package.json`);
      return path.dirname(pkgFile);
    } catch {
      return null;
    }
  }

  // ---------- 市场注册表（带缓存，失败不影响体检） ----------
  let cache = { at: 0, plugins: [] };
  async function marketEntry(nameOrUrl) {
    if (Date.now() - cache.at > 10 * 60 * 1000) {
      try {
        const mod = await import('node:http');
        const body = await new Promise((resolve) => {
          const req = mod.default.get(
            { host: '127.0.0.1', port: marketPort, path: '/dsh-market/registry', headers: { host: `127.0.0.1:${marketPort}`, accept: 'application/json' }, timeout: 20000 },
            (res) => {
              let d = '';
              res.setEncoding('utf8');
              res.on('data', (c) => (d += c));
              res.on('end', () => resolve(d));
            },
          );
          req.on('error', () => resolve(''));
          req.on('timeout', () => {
            req.destroy();
            resolve('');
          });
        });
        const parsed = body ? JSON.parse(body) : null;
        cache = { at: Date.now(), plugins: parsed?.registry?.plugins ?? [] };
      } catch {
        cache = { at: Date.now(), plugins: cache.plugins };
      }
    }
    if (!nameOrUrl) return undefined;
    const lower = String(nameOrUrl).toLowerCase();
    return cache.plugins.find((p) => String(p.npm || '').toLowerCase() === lower || String(p.url || '').toLowerCase().includes(lower));
  }

  // ---------- 工具 ----------
  let tools;
  try {
    tools = ctx.get('tools');
  } catch {
    tools = undefined;
  }

  if (!tools?.register) {
    log('⚠️ tools 服务不可用，warden_audit 未注册');
    return;
  }

  tools.register({
    name: 'warden_audit',
    description:
      'Security review of a DSH plugin before enabling it: reads its package.json, install hooks, native deps, '
      + 'source for network egress / dangerous APIs / credential paths, cross-checks the curated market registry, '
      + 'and returns a score, a verdict (safe / caution / risky) and itemised findings. Read-only: it never executes '
      + 'the audited code and never modifies files.',
    parameters: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'Installed package name (e.g. "dsh-ego-browser") or an absolute plugin directory.' },
      },
      required: ['target'],
      additionalProperties: false,
    },
    output: {
      schema: {
        type: 'object',
        properties: {
          ok: { type: 'boolean' },
          verdict: { type: 'string' },
          score: { type: 'number' },
          report: { type: 'string' },
        },
        required: ['ok', 'report'],
        additionalProperties: true,
      },
      render: (_args, value) => [{ type: 'text', text: value?.report ?? '(无报告)' }],
    },
    async execute(args) {
      const target = typeof args?.target === 'string' ? args.target.trim() : '';
      if (!target) throw new Error('warden_audit: target 不能为空');

      const dir = resolveTarget(target);
      if (!dir) throw new Error(`找不到插件：${target}（既不是绝对目录，也不在 profile 的 node_modules 里）`);

      const entry = await marketEntry(target);
      const result = auditPlugin(dir, entry);
      const report = renderReport(result);
      log(`审计 ${target} → ${result.verdict} (${result.score})`);
      return { ok: result.ok !== false, verdict: result.verdict, score: result.score, report };
    },
  });

  log(`✅ warden_audit 已注册（profile: ${profileDir}）`);
}
