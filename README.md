# EIDOVELA Open

## EIDOVELA — Agent Identity Provider (IdP)

**EIDOVELA** is a native Agent Identity Provider (IdP) and authentication authority for agent-based systems. It manages agent lifecycles, issues short-lived Proof-of-Possession (PoP) bound tokens, and enforces tenant-scoped trust domains.

与通用 IdP 不同，EIDOVELA 专为 agent-based 系统设计，提供：

- **Agent 生命周期管理** — Register / Enroll / Activate / Suspend / Revoke agents
- **tenant-scoped trust domains** — 仅在 `tenant_trust_domains` 表中验证的 trust domains
- **Platform 识别** — kubernetes / spiffe / mTLS 工作负载证明
- **private_key_jwt enrollment** — 安全的 JWT-based proof-of-possession enrollment
- **Lifecycle-aware token issuance** — tokens 绑定到 agent 生命周期状态和 epoch
- **Federation foundation** — 经验证的 downstream federation 和 console 工作流

**License:** Apache-2.0 — 源可用，企业功能 (HSM/KMS 适配器、高级 federation、console) 驻留在 `eidovela-ee`。

**Module:** `github.com/axisrobo/eidovela-open`

---

## eidovela-open

This repository (`eidovela-open`, Apache-2.0) publishes the public contracts, SDKs, and client libraries that consume the core EIDOVELA authority — a native Agent Identity Provider (IdP) for agent-based systems.

它包括：

- OIDC discovery and introspection APIs (audience-aware verification)
- SDKs for Agent/workload token exchange (private_key_jwt, PoP key generation)
- Protocol conformance (JWT, mTLS, SPIFFE workload attestation)
- Documentation and examples for the local identity loop

**Public API surface:** introspect, token exchange, federation handoff, audience-aware verification.

**Docs (Chinese):** <https://github.com/axisrobo/eidovela/blob/main/docs/README.md>

**Topics:** `eidovela` `identity` `authentication` `oidc` `workload-attestation` — see the [Chinese docs](https://github.com/axisrobo/eidovela/blob/main/docs/README.md) for full reference.
