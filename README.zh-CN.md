# EIDOVELA Open

[English](README.md) · [简体中文](README.zh-CN.md)

---

## EIDOVELA — Agent 身份提供商（IdP）

EIDOVELA 是为基于 Agent 的私有云系统打造的原生 **Agent 身份提供商（IdP）与认证权威（Authentication Authority）**。与通用的 OIDC IdP 不同，EIDOVELA 围绕 *Agent 与人不同的本质* 而设计：

- **Agent 生命周期管理** —— Agent 沿 Register → Enroll → Activate → Suspend → Revoke 流转，每一张下发的身份都与生命周期状态绑定。
- **租户范围内的信任域（tenant-scoped trust domains）** —— 仅接受为租户显式配置的信任域（`tenant_trust_domains`）；工作负载无法加入它从未被信任的租户。
- **平台识别（platform recognition）** —— 工作负载证明能够理解运行平台（kubernetes、spiffe、mTLS），只有当工作负载的平台属性与其注册的选择器匹配时，才会签发身份。
- **private_key_jwt 登记** —— 基于密钥持有证明（proof-of-possession）的登记：Agent 先证明其掌控对应私钥，才颁发绑定 PoP 的凭据。
- **生命周期感知的令牌签发** —— 短时效令牌与 Agent 的 epoch 和状态绑定；被暂停或吊销的 Agent 无法获得有效令牌。
- **联邦基础（federation foundation）** —— 为联邦与 Console 工作流提供可信的下游验证。

### EIDOVELA 解决什么问题？

Agent 系统面临通用 IdP 无法回答的身份问题：*「谁被允许在这个租户内、以这个平台上运行的该工作负载的身份，充当这个 Agent？」* EIDOVELA 通过把 Agent 身份与其生命周期、租户信任域、以及运行它的工作负载的平台证明紧密绑定来回答该问题——让认证（“是谁”）成为授权（“能做什么 / 在何处”）的可信输入。

**身份 / 认证 = EIDOVELA · 授权 / 委托 = AEGIVELA**（Agent IAM）。

---

## eidovela-open

本仓库（`eidovela-open`，Apache-2.0）是 EIDOVELA 面向开发者/公众的分发仓库：面向消费核心权威的版本化公共契约、SDK、CLI、示例与一致性（conformance）测试夹具。

目录内容：

- `contracts/` —— 版本化公共契约 schema（v1 稳定版；保留 v1alpha1）
- `sdk/go` —— Go SDK（HTTP 客户端、Ed25519 PoP 密钥生成、离线 JWT/JWKS 校验、RFC 8693 令牌交换 profile）
- `cli/` —— 命令行工具
- `examples/` —— 集成示例
- `conformance/` —— 可执行的威胁场景测试夹具 + 驱动真实守护进程的 HTTP runner（`cmd/eidovela-conformance`）；附带预构建的核心守护进程（`conformance/bin/`）

核心服务端实现位于 AGPL 仓库：<https://github.com/axisrobo/eidovela>

### 公共 API 面

- 权威 introspection（绑定 audience）
- RFC 8693 令牌交换（拒绝 audience 放大）
- OIDC discovery 与 JWKS
- 联邦移交（federation handoff）

---

## 版本规则

- 格式：`major.minor.patch`
- **`eidovela-open` 与 `eidovela`（core）共享同一版本标签**（如 `v0.5.0`）。
- `eidovela-ee`（企业版）可拥有独立的版本/标签。

## 快速开始 — 本地环回

先启动核心守护进程，再运行公共示例：

```text
eidovelad
go run ./examples/local-loop
```

该示例会注册一个 Service Agent、注册一条工作负载 profile、完成
`private_key_jwt` 登记、激活 Agent、获取短时效 PoP 绑定令牌，然后进行权威 introspection。

登记时提供的工作负载属性必须与已注册工作负载 profile 上的每个选择器完全匹配；调用方无法仅凭一个 Agent ID 绕过工作负载绑定。

Go SDK 位于 `sdk/go/eidovela`。离线校验不检查当前生命周期 epoch；高风险消费方必须使用权威 introspection。

---

- 许可证：Apache-2.0
- 模块：`github.com/axisrobo/eidovela-open`
- 分发治理：`STATUS.md`、`COMPATIBILITY.md` 与 `contracts/README.md`
