# PACC Binary Protocol

> 面向 PACC 全平台反作弊系统的统一二进制通信协议，提供多语言运行时与 MDL 代码生成器。

[![Languages](https://img.shields.io/badge/languages-C%23%20%7C%20Java%20%7C%20Python%20%7C%20Rust%20%7C%20TypeScript-blue)](https://github.com/EPOTATOTV/PACC_PBP)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Protocol](https://img.shields.io/badge/protocol-PBP-green)](https://github.com/EPOTATOTV/PACC_PBP)
[![Codegen](https://img.shields.io/badge/codegen-MDL-orange)](https://github.com/EPOTATOTV/PACC_PBP/tree/main/pacc-binary-protocol/mdl)

## 项目简介

PACC Binary Protocol（PBP）是 PACC 反作弊体系中的底层通信协议层，用于在玩家端探针、管理后端与跨平台更新服务之间高效、可靠地传输结构化数据。

PACC 主体采用「统一核心引擎 + 平台适配层」架构，一套核心逻辑在 Windows、Android、iOS、iPadOS、HarmonyOS 上运行[reference:0]。PBP 在这一体系中承担**数据通道**的角色：将检测结果、心跳状态、远程指令等消息序列化为紧凑的二进制格式，通过 WebSocket 长连接在客户端与服务端之间双向传输。

与基于文本的 JSON 或 XML 方案相比，PBP 的二进制编码显著降低带宽占用与序列化开销，同时借助 MDL（Message Definition Language）代码生成器，为 C#、Java、Python、Rust、TypeScript 五种语言自动生成类型安全的编解码运行时，消除跨语言协议实现不一致的风险。

## ✨ 核心特性

- **二进制编码**：紧凑的消息格式，比 JSON 减少 60%–80% 的传输体积，适合心跳等高频小包场景
- **五语言运行时**：同一套协议定义，自动生成 C# / Java / Python / Rust / TypeScript 运行时，编解码行为完全一致
- **MDL 代码生成器**：声明式消息定义语言，通过 `pbpgen` 工具生成各语言代码，协议变更无需手动修改五份实现
- **Zstandard 压缩**：内置 Zstd 压缩层，对大体积检测报告等消息自动压缩
- **测试向量交叉校验**：提供跨语言测试向量（test-vectors），确保五种运行时对同一二进制流的解析结果逐字节一致
- **无外部依赖**：各语言运行时均为纯实现，不依赖第三方序列化库，便于嵌入探针与客户端

## 架构设计

PBP 遵循三条设计约束：

- **协议与实现分离**：消息结构由 MDL 文件定义，各语言运行时由生成器产出，协议变更只改一处
- **跨语言一致性优先**：任何编解码逻辑都必须通过全部五种语言的交叉测试向量验证
- **面向 PACC 场景优化**：消息字段针对检测数据、心跳、远程指令等实际载荷设计，不做通用序列化框架

## 技术栈

| 层级 | 技术 |
|---|---|
| 协议定义 | MDL（Message Definition Language） |
| 代码生成器 | Python（`tools/pbpgen`） |
| 运行时语言 | C# / Java / Python / Rust / TypeScript |
| 压缩 | Zstandard |
| 测试 | 跨语言测试向量交叉校验 |

## 目录结构

```
PACC_PBP/
├── pacc-binary-protocol/
│   ├── mdl/                  # MDL 协议定义文件
│   ├── runtime-csharp/       # C# 运行时
│   ├── runtime-java/         # Java 运行时
│   ├── runtime-python/       # Python 运行时
│   ├── runtime-rust/         # Rust 运行时
│   ├── runtime-ts/           # TypeScript 运行时
│   ├── test-vectors/         # 跨语言测试向量
│   └── tools/zstd-crosscheck # Zstd 交叉校验工具
├── tools/pbpgen/
│   ├── pbpgen/               # MDL 代码生成器
│   └── tests/                # 生成器测试
└── .gitignore
```

## 快速开始

### 环境要求

- **Python 3.10+**（运行 MDL 代码生成器）
- **目标语言工具链**：.NET SDK / JDK 17+ / Rust / Node.js 18+ 中的任意组合，取决于你需要生成哪些语言的运行时

### 使用 pbpgen 生成运行时代码

```bash
cd tools/pbpgen
pip install -e .
pbpgen generate --mdl ../pacc-binary-protocol/mdl --lang all --out ../pacc-binary-protocol
```

`--lang` 可指定单一语言（如 `--lang java`）或 `all` 生成全部五种运行时。

### 运行测试向量校验

```bash
# 以 Python 运行时为例
cd pacc-binary-protocol/runtime-python
python -m pytest tests/
```

各语言运行时的测试入口详见对应目录下的 README。

## 贡献指南

1. Fork 本仓库
2. 创建分支 `git checkout -b feature/xxx`
3. 提交改动 `git commit -m "feat: xxx"`
4. 推送分支 `git push origin feature/xxx`
5. 提交 Pull Request

> 修改 MDL 定义或生成器逻辑时，必须确保全部五种语言的测试向量通过交叉校验。

## 许可证

本项目基于 [GNU Affero General Public License v3.0（AGPLv3）](https://github.com/EPOTATOTV/PACC_PBP/blob/main/LICENSE) 开源。

## 致谢

- [Zstandard](https://facebook.github.io/zstd/)
- PACC 全体贡献者
