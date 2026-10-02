# Varwof AIC —— 能力语义演示包

> Varwof AIC 套件的一部分 —— 旗舰仓库：[aic-agent](https://github.com/varwof/aic-agent) · [aic-verifier](https://github.com/varwof/aic-verifier) · [aic-exec](https://github.com/varwof/aic-exec)

> ⚠️ **预览版** — 不可用于生产环境。API 和功能可能在正式发布前发生变更。

AIC 能力授权语义的端到端可运行演示：**AI 提出最小权限 → 工具校验（版本锁定）→ 角色授予求交
→ 密码学绑定进 AIC → 网关按请求执行**。四个场景：数据库、数字钱包、部署/基础设施、MCP 工具
调用。所有环节可复现、可审计。

[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

[English](README.md)

本包消费 [`varwof/capability`](https://github.com/varwof/capability) 的能力数据与一致性语料，
并实现与 Go 参考实现 [`varwof/register`](https://github.com/varwof/register) 相同的 CLC-v1 语义。

## 0. 克隆并运行（新机器三步）

```bash
git clone https://github.com/varwof/aic-capability-demo.git && cd aic-capability-demo
# 1) 从锁定 commit 构建全部二进制（一条命令）
./build.sh && export PATH="$PWD/bin:$PATH"
# 2) 初始化 CA，签发主体证书（REVIEWER-GUIDE §6）
# 3) 由你用 CA 签发的证书生成网关配置
./setup.sh --gateway-cert gw.pem --gateway-key gw.key --jwt-ca issuing-ca.pem
# 4) 启动后端 + 网关，运行任一场景
python3 backends.py &
gateway-http --config gateway.json &      # 在本目录下运行（capdata 路径为相对路径）
python3 scenario-demo.py --scenario mcp --principal-cert principal.pem \
  --principal-key principal.key --client-config client.json --ca-cert ca-bundle.pem \
  --pa-authz --execute
```

- `capdata/` 下的 `.p7s` 文件由 `capdata/trust/demo-codesign-ca.pem` 签名，开箱即可验签通过。
- 各脚本默认使用包内的 `capdata/`；只有 `gen-capability` 需要 register 仓（自动探测为
  `../register` 或本地 checkout）。
- `gateway.json` 由 `setup.sh` 从 `gateway.json.template` 生成 —— 不含任何绝对机器路径。

## 1. 这是什么

```
 DeepSeek / mock              register 工具              core (CA)               gateway-http
      |                            |                          |                       |
 task + prompt + spec         claims.json              PA 签 DA -> CA 签发 AIC   Bearer AIC-JWT
      |  ----------------->  gen-capability -minimal -> 参数绑定进证书 -------> capability 插件
      |                       (scheme_version 锁定)      --pa-authz 角色求交      (越界 -> 403)
```

## 2. 能力场景（5 个 scheme）

| 场景 | scheme | 能力 | 强制参数 |
|---|---|---|---|
| 数据库 | `std/database-v1` | query:SELECT/INSERT/UPDATE/DELETE/EXECUTE, admin:DDL/TRUNCATE | 见下表 |
| 数字钱包 | `std/wallet-v1` | balance / transfer / history | assets、networks、max_amount_per_tx、recipients 白名单 |
| 部署/基础设施 | `std/deploy-v1` | deploy:apply / infra:read / secret:read | environments、namespaces、resources、max_replicas、secrets 白名单 |
| MCP 工具 | `std/mcp-v1` | tools:call | tools 白名单（声明为空即拒绝）+ tool_args/path_prefixes |
| LLM | `varwof/llm` | chat | model、max_tokens |

数据库 scheme **不是**共用一套参数——每个能力各自声明 required 键，缺少任一 required 的请求
会被网关拒绝。读自 `capdata/std/database-v1/v1.json`：

| 能力 | required | optional |
|---|---|---|
| `query:SELECT` | `tables`、`columns` | `aggregate`、`row_filter`、`filter_columns`、`limit` |
| `query:INSERT` | `tables`、`columns` | — |
| `query:UPDATE` | `tables`、`columns`、`row_filter` | `filter_columns`、`limit`、`order_by` |
| `query:DELETE` | `tables`、`row_filter` | `filter_columns`、`limit`、`order_by` |
| `query:EXECUTE` | `procedures` | — |
| `admin:DDL` | `operations`、`tables` | — |
| `admin:TRUNCATE` | `tables` | — |

注意：上游 [`varwof/capability`](https://github.com/varwof/capability) 把本包的 LLM scheme
命名为 `varwof/llm-v1`；而内置在 `capdata/` 里的那份仍沿用旧的 `varwof/llm` 标识。

## 3. 文件

| 文件 | 用途 |
|---|---|
| `REVIEWER-GUIDE.md` | 独立评审者走查（构建/CA/签发/网关/矩阵）；2026-09-01 已验证 |
| `QUICKSTART.md` | 两条命令快速上手 + 各场景矩阵 |
| `deepseek-capability-aic.py` | 数据库场景端到端（DeepSeek/mock → 校验 → AIC） |
| `wallet-demo.py` | 钱包场景端到端 + 6 例矩阵 |
| `scenario-demo.py` | 部署/MCP 场景（`--scenario deploy\|mcp`） |
| `backends.py` | 模拟后端：data :9100 / LLM :9200 / wallet :9300 / deploy :9400 / MCP :9500 |
| `build.sh` | 从锁定 commit 一条命令构建全部二进制 |
| `gateway.json.template` + `setup.sh` | 可移植的网关配置生成 |
| `capdata/` | 能力 scheme + PKCS#7 签名 + 演示信任根 |

### CLC-v1 实现与 runner

| 文件 | 用途 |
|---|---|
| `clc_semantics.py` | Python CLC-v1 实现（下列各项的参照） |
| `vectors-run.py` | CLC-A 授权语料 runner |
| `resolve-vectors-run.py` | §8.5 `Resolve` runner |
| `param-bounds-vectors-run.py` | §6.5 参数界 runner |
| `param-bounds-meet-vectors-run.py` | §6.6 `BoundMeet` runner |
| `constraint-union-vectors-run.py` | §7.1 `ConstraintUnion` runner |
| `contains-vectors-run.py` | §13 `Contains` runner |
| `authorize-chain-vectors-run.py` | §13.11 `AuthorizeWithChain` runner |
| `property_test.py` | P11 属性 runner（1184 例：收窄性 + 顺序无关性） |
| `param-bounds-meet-property-run.py` | §6.6 meet 不变式属性 runner（500 例） |
| `contain-property-run.py` | CLC-D 前向闭包属性 runner（784 例） |
| `edge_test.py` | raw/解码边界套件（非有限值、非法 Unicode、JCS 大小、params **与约束**中的 I-JSON 整数界） |
| `contains_test.py` | 与 Go 参考实现的包含关系一致性检查 |
| `jcs_check.py` | RFC 8785（JCS）规范化：字节、摘要、`clc-action:` id、键序、非法 Unicode |
| `ts/` | 上述全部的 TypeScript 镜像（仅 Node，零 npm 依赖） |
| `fuzz/` | 确定性差分模糊测试框架（`gen_cases.py`、`run_py.py`、`run_ts.ts`、`compare.py`、`shrink.py`） |
| `clc-v1-parity-report.md` | 跨实现一致性记录 |
| `fuzz-divergence-report.md` | 当前锁定点上的差分模糊结果，含仍未关闭的发现 |

本包只为自己实现的语料提供 runner；证据侧（`evidence-vectors.json`）与 crosswalk
（`crosswalk-vectors.json`）语料由 [`varwof/register`](https://github.com/varwof/register)
中的 Go runner 运行。

## 4. 验证矩阵（全部通过）

- **database**：范围内 200；越界的表/列/limit 403（body 与 query 两种路径）
- **wallet**：范围内转账 200；超额 / 非白名单收款方 / 未授权资产 403；余额 200/403
- **deploy**：staging 200；production / 越界命名空间 / 超副本数 403；secret 白名单 200/403
- **mcp**：read_file/list_dir 200；bash/delete_file 403；initialize 协议 200；
  恶意边界（v0.4.6）：缺 params.name / 声明为空的白名单 / `/workspace-evil` 同级目录 /
  `/workspace/../etc` 父目录穿越 → 403
- **重放保护**：同一 JWT 两次 → 先 200 后 401

## 5. 结论背后的实现 commit

| 仓库 | Commit | 提供什么 |
|---|---|---|
| varwof/register | 954951f / edaa378 / 71c0f39 | 扁平参数值校验、params_schema 校验、scheme_version 锁定 |
| varwof/types | addb8b0 / 4868765 | capability/grant JSON 容器参数；HTTPFacts/PluginContext body |
| varwof/client | 44b210b / 6b74b23 / 9dbd21e | caps/pa JSON 参数、--from-claims、--pa-authz 角色求交 |
| varwof/core | 1a6cbe7 / ed42b00 | 签发时的通用参数子集；签发审计中的 claims 摘要 |
| varwof/gateway-core | v0.4.1–v0.4.6 (9674d7c) | database/wallet/deploy/mcp 插件；bearer fail-closed；恶意路径/白名单边界修复 |
| varwof/gateway | 763b6ce / 779481d / a35d9c6 | body 透传插件；capreg .p7s 验签；插件接线 |
| varwof/capability | 10162b5 / d225486 / d8bd1c3 / f124868 / 24a9ca9 | std/database-v1、std/wallet-v1、std/deploy-v1、std/mcp-v1（v1.1.0 文档）、varwof/llm |

## 6. 已演示的安全属性

1. 能力参数以密码学方式绑定进 AIC/PA/DA（claims 摘要锚定在 DA reason 与签发审计中）
2. CA 拒绝超出操作者角色授予范围的 claims（`--pa-authz`，Pprincipal ∩ Cagent）
3. 网关按请求执行参数边界
4. 注册表 PKCS#7 签名验证（被篡改即 fail-closed）
5. Bearer 重放保护 + 明文拒绝

## 7. 已知边界

- 网关只提供自己的叶证书：请把 root + intermediate 打成 bundle 传给 `--ca-cert`
- mcp 插件把没有 JSON-RPC body 的请求当作协议方法
- 限流（钱包每日、mcp rpm）目前只是参数占位，尚未强制
- 插件使用结构化 operation payload；真实 SQL/钱包/部署 API 需要各自的适配器

## 8. CLC-v1 实现与一致性语料

三个实现跑**同一批**语料，并断言 **verdict、规范 reason code 与求交后的交集结果**：

| 实现 | 位置 | 向量 runner | 属性 runner |
|---|---|---|---|
| Go | `varwof/register`（`semantics/`） | `go run ./cmd/vectors-run/` | `go test ./semantics/ -run TestIntersectionProperty` |
| Python | 本仓 | `python3 vectors-run.py` | `python3 property_test.py` |
| TypeScript | `ts/`（Node 22 `--experimental-strip-types`，零 npm 依赖） | `node --experimental-strip-types ts/vectors-run.ts` | `node --experimental-strip-types ts/property.ts` |

```bash
# 三个实现，跑 varwof/capability 里的共享语料
export CLC_VECTORS=../capability/data/_vectors/clc-v1/vectors.json
export CLC_PROPERTY_CASES=../capability/data/_vectors/clc-v1/property-cases.json
python3 vectors-run.py && python3 property_test.py
node --experimental-strip-types ts/vectors-run.ts && node --experimental-strip-types ts/property.ts
(cd ../register && go run ./cmd/vectors-run/ && go test ./semantics/ -run TestIntersectionProperty)
# RFC 8785 规范化（rev CLC-1.6）：Go、Python 与 TypeScript 必须产出
# 相同的 JCS 字节、摘要与 clc-action: 标识。
python3 jcs_check.py && node --experimental-strip-types ts/jcs_check.ts
```

语料（位于 [`varwof/capability`](https://github.com/varwof/capability) 的 `data/_vectors/`）：
`clc-v1/vectors.json`（CLC-A 授权向量，含 rev CLC-1.3 的 `allow_unresolved` verdict 与 §9.1
多 grant 聚合——**146 条**；权威计数以该仓 README 为准）、`evidence-vectors.json`（32）、
`crosswalk-vectors.json`（13）、`param-bounds-vectors.json`（43）、
`param-bounds-meet-vectors.json`（27）、`param-bounds-equality-vectors.json`（11）、
`constraint-union-vectors.json`（12）、`constraint-union-collation-vectors.json`（2）、
`resolve-vectors.json`（26）、`property-cases.json`（1184 条确定性 P11 用例）、
`param-bounds-meet-property-cases.json`（500）、`offline-vectors.json`（12 条 OCMP 参考
用例），以及 `clc-d/` 下的 `containment-vectors.json`（64）、
`authorize-chain-vectors.json`（15）、`containment-crosswalk-vectors.json`（44）、
`containment-property-cases.json`（784）。

用环境变量把语料指给 runner —— 每份语料对应的变量见
[`varwof/register`](https://github.com/varwof/register#conformance-corpora)：

```bash
export CLC_VECTORS=../capability/data/_vectors/clc-v1/vectors.json
python3 vectors-run.py
export CLC_D_VECTORS=../capability/data/_vectors/clc-d/containment-vectors.json
python3 contains-vectors-run.py
```

为什么是三个：一门语言的强度，只取决于它的解释器之间的一致程度。这三个实现出自同一作者，
因此它们的一致性是对规范的回归测试，而不是独立验证（§12，原则 P12）—— 即便如此，它们在
2026-09-11 之前仍在真实输入上产生过分歧：Go 与 Python 实现各自违反了 TypeScript 实现已经
遵守的规则（布尔精确性、第 6 层先于第 7 层、第 1 层错误码传播）。一致性记录见
`clc-v1-parity-report.md`；`.github/workflows/clc-conformance.yml` 中的 CI 会克隆
`varwof/capability`，在每次 push 与 PR 上运行 `py_compile`、向量与属性套件。

## 9. 差分模糊测试（行为级一致性）

上面的向量断言三个实现产出*相同答案*。模糊测试框架问的是更难的问题：在没人写过向量的输入
上，它们的行为是否仍然一致，包括 reason code 与值层。

```bash
python3 fuzz/gen_cases.py --n 100000 --seed 20260915 > /tmp/cases.jsonl
python3 fuzz/run_py.py /tmp/cases.jsonl > /tmp/res_py.jsonl
npx --yes tsx fuzz/run_ts.ts /tmp/cases.jsonl > /tmp/res_ts.jsonl
(cd ../register && go run ./semantics/fuzz_runner /tmp/cases.jsonl > /tmp/res_go.jsonl)
python3 fuzz/compare.py /tmp/cases.jsonl /tmp/res_py.jsonl /tmp/res_ts.jsonl /tmp/res_go.jsonl
```

语料由 seed 确定性生成，覆盖十个轴（键序、重复键、畸形转义与孤立代理项、数值形状、
缺失/null/空、类型、数组、大小与深度上限、约束标识、id 形状）。
`fuzz-divergence-report.md` 记录当前锁定点的结果，包括仍未关闭的发现。单个实现内部的
raw/解码边界差异是 CLC §6.2 按设计工作，不是分歧；该报告把两者分开，避免计数被误读。

## 10. 相关仓库

| 仓库 | 是什么 |
|---|---|
| [`varwof/capability`](https://github.com/varwof/capability) | 本包消费的能力 scheme 与全部 CLC-v1 一致性语料（[English](https://github.com/varwof/capability/blob/main/README.md)） |
| [`varwof/register`](https://github.com/varwof/register) | 同一套 CLC-v1 语义的 Go 参考实现（[English](https://github.com/varwof/register/blob/main/README.md)） |

## 链接

| | |
|---|---|
| 主页 | https://varwof.com |
| 社区 | https://varwof.org |
| 许可证 | Apache-2.0 |
| 成员 | [Open Invention Network](https://openinventionnetwork.com/) |