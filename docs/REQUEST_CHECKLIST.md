# Requested-change checklist

Verified on 2026-09-09 against the current `/root/grypton` checkout. The
machine-readable source of truth is
[`verification/request-audit.json`](verification/request-audit.json).

| Request | Result | Verification |
| --- | --- | --- |
| Create `/root/grypton` from the Krypton codebase without target data | Implemented as a separate active package with an inactive 28-file source snapshot. All 39 recorded non-target source files were inspected and remain unchanged. The 11 omitted launch/helper files are listed in the parity audit. | `grypton audit --auth`; `FORK_MANIFEST.json`; `krypton-source-audit.json` |
| Do not read or copy targets | Verified. The recorded audit opens only its explicit 39 source paths and rejects target/session/runtime paths. No target data is in the snapshot or package. | Integrity audit; import path tests |
| Create only an empty `target/` | Verified. `/root/grypton/target` exists and is empty; `/root/grypton/targets` is absent. | Integrity audit and terminal walkthrough |
| Kraude uses GLM-5.3 max on Z.AI Coding Plan | Verified live and structurally: `zai-coding-plan/glm-5.3`, `max`, through OpenCode. | `doctor`; live role check; route tests |
| Kryptex uses Muse Spark 1.3 xhigh on OpenCode Go | Verified live and structurally: `opencode-go/muse-spark-1.3-contributor`, `xhigh`. The Go connector matches a value in `/root/open`; values are withheld. | `doctor`; `live-kickoff.json`; integrity audit |
| Kryptex manages Kraude and acts on operator intent | Implemented. Natural task directives are persisted before interpretation. Kryptex delegates immediately, returns local resources to Kraude, and records the relay. Passive Spark refusals are replaced before persistence or display and cannot prevent delegation. | `live-kickoff.json`; pseudo-TTY and regression tests |
| Resolve blockers without routine operator setup | Implemented for existing evidence, private scratch space, synthetic `.invalid` email, offline identity, and temporary text fixtures. Up to three sequential chat calls can resolve multiple local requests. External resources remain explicit gaps. | blocker tests and console resource log |
| Validate findings with GPT-6 Astra max | Implemented as Kryptex plan → independent Astra validation → Kryptex summary. Astra receives only claim and selected evidence. | `live-finding-validation.json`; validator-independence tests |
| Improve CLI | Implemented positional and `--target` init, automatic scope, persistent console, multiline paste, observations, surface, findings, history, resources, stop/resume, lab, audit, JSON, and role launchers. | 56 tests and `console-check.json` |
| Improve UI | Implemented a responsive local operations console with routes, search/filtering, scope, surface, finding ledger, call audit, resource decisions, system integrity, and validation lab. | `browser-check.json`; desktop/mobile screenshots |
| Enhance scenarios | Implemented five walkthrough scenarios plus a fixed three-scenario/nine-transition scored lab with deterministic 13-component evaluation. | `lab verify`; `lab-check.json` |
| Enhance prompts and skills | Implemented role-specific prompt bundles with eight skills: coordination, blockers, scope, evidence, hypotheses, remediation, severity, and validation handoff. Fingerprints are stored with every run. | Integrity audit and prompt-provenance tests |

The active runtime remains a supplied-material workflow. It does not autonomously
probe or exploit live targets, create real accounts, or acquire external
identities. The fixed lab measures structured behavior on synthetic evidence; no
claim of equal vulnerability-discovery accuracy is made.
