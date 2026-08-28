# ADCOS Current Work Item Execution Status

**Baseline:** `main@62f5b9d3075871a9f06d9806f51b37658a6995cc`.

This derived snapshot never overrides live GitHub/Architect state.

| Work Item | Current state | DAG / semantic readiness | Execution readiness | Evidence class |
|---|---|---|---|---|
| W030 | Open PR #32; Architect re-review pending; **not accepted** on current `main` | Not satisfied for downstream execution until accepted | Active/reviewing; not complete | Automated + architecture; frozen W030 external rule only |
| W031 | Next simulator target | DAG-ready: W007/W011/W012/W013/W027 accepted | Blocked while W030 is active and by one-WI execution governance | Automated/deterministic; no external evidence required |
| W032 | Conformance target | Graph-satisfied by current graph, but OAQ-001 records a frozen backlog-vs-DAG dependency declaration inconsistency for W016 | Blocked while another WI is active; OAQ-001 must not be silently resolved | Automated/conformance |
| W033 | Linux Agent | Blocked by W030/W032 and frozen DAG | Blocked | Automated/end-to-end Linux |
| W034 | Raspberry Pi / low-power gateway | Blocked by W020/W021/W022/W023/W024/W033 | Blocked | Hardware integration / external evidence |
| W035 | Android/mobile Agent | Blocked by W012/W013/W018/W033 | Blocked | Mobile lifecycle / device evidence where required |
| W036 | Network-in-a-Box | Blocked by W024/W025/W030/W033/W034 | Blocked | Isolated-site integration |
| W037 | Open RAN/Core interoperability | Blocked by W019/W020/W021/W032/W033 | Blocked | **Real 5G lab external evidence required** |
| W038 | Future IMT / 6G adapter profile | Blocked by W016/W029/W032/W033 | Blocked | Synthetic conformance |
| W039 | Federation at scale | Blocked by W015/W031/W033/W036 | Blocked | Large-scale simulation/integration |
| W040 | Pilot deployment | Blocked by W027/W028/W036/W037/W039 | Blocked | **Real pilot external evidence required** |

## Status semantics

- **DAG-ready** means the frozen graph's hard prerequisites are satisfied; it does not authorize implementation.
- **Execution-ready** additionally requires explicit Architect designation under the one-active-Work-Item rule.
- **Accepted** requires explicit Architect acceptance plus the applicable architecture/verification/external-evidence record.
- A merge, green CI run, or closed PR never substitutes for Architect acceptance.
