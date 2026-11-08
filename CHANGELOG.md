# Changelog

## 0.1.1 — 2026-11-08

- 声明 `inject = ['tools']`，确保 tools 服务就绪后再注册工具（修复隔离 profile 启动时报「tools 服务不可用」）。

## 0.1.0 — 2026-11-04

首个版本。

- 92feda2 chore: add repository metadata
- 6e53924 fix(warden): skip self-scan false positives in rule tables
- a0b1dd9 feat: initial release

