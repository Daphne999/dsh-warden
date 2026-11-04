# dsh-warden

> 装插件前的安全体检。读代码、给结论，**不执行、不代理、不改任何东西**。

DSH 插件跑在宿主进程里 —— 一旦启用，就等于把 shell、文件系统、网络、凭据全交出去。市场里的插件鱼龙混杂，安装脚本、原生模块、外联域名、危险 API 都可能藏着东西。

`dsh-warden` 做的事很简单：**在你点「启用」之前，把那个包摊开看一眼。**

- 读 `package.json`：安装期脚本、原生依赖、manifest 是否完整
- 扫源码：外联域名、`child_process` / `eval` / `vm` / 动态 Function、递归删除、写启动项、凭据路径
- 交叉核对市场注册表：能力声明、红线标记、star 数、是否走 git 安装
- 输出：**100 分制评分 + safe / caution / risky 判定 + 逐条发现**

## 装

```bash
dsh plugin --profile web add dsh-warden
```

## 用

装好后，agent 会获得一个工具：

```
warden_audit { "target": "dsh-ego-browser" }
```

`target` 可以是已安装的包名，也可以是插件的绝对路径（本地开发调试用）。

输出示例：

```
⚠️ dsh-ego-browser v0.9.8 —— 评分 74/100（caution）
license: MIT | 扫描文件 2 个
🟠 源码用到「child_process」：lib\index.js
🟠 源码用到「execSync / spawnSync」：lib\index.js
🟠 市场标注它拥有 shell 执行能力
ℹ️ 会连接 4 个外部域名：gh-proxy.com, www.w3.org, dsh.internal, example.com
```

## 它是怎么打分的

| 信号 | 权重 |
|---|---|
| 安装期脚本（preinstall / install / postinstall / prepare） | 高 |
| 凭据路径（`.ssh` / `.env` / `credentials.yaml` / `.npmrc`） | 高 |
| `eval` / `new Function` / `vm` / 写注册表或计划任务 | 高 |
| 市场红线标记、声明 `credentials` 能力 | 高 |
| `child_process` / 递归删除 / 原生模块 / 声明 `shell` 能力 | 中 |
| 外联陌生域名、star 过少、只走 git 安装、不在精选目录 | 低 |

> 判定：≥75 `safe`，≥50 `caution`，否则 `risky`。**分数不是判决书** —— 一个浏览器驱动插件用 `child_process` 是本职，但它确实比一个纯 UI 插件危险。看到 `caution` 不代表有毒，代表你该知道它在干什么。

## 它不做什么

- **不执行**被审计插件的任何代码（只做静态读取）
- **不代理**下载、不改 package.json、不动 node_modules
- 不做真实沙箱 —— 它给的是"读得出来的风险"，不是行为分析

## 原理：为什么不用 unshare/容器

插件的风险大多写在源码里（脚本、域名、危险 API），静态扫描能覆盖 80% 的低成本判断；真要做行为沙箱，得拉容器、跑 syscall 追踪，代价比收益大。这个插件的定位是"几十毫秒的体检"，不是"安全审计报告"。

## License

MIT
