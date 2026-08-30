# ADCOS Architect Review Protocol

## Status

**ACTIVE — Persistent Governance Authority (process layer; follows the frozen Architecture Version 1.0)**

This is the persisted Architect review protocol for ADCOS. Every review of
an implementation PR, a governance PR, or an ACR follows this protocol. It
operationalizes `spec/workflow.md` §4 and `spec/dependency-graph.md` §7
(the review gate) and adds the persistence obligations of the persistent
Architect package.

---

## 1. Mandatory review dimensions

Every review must evaluate at least:

```text
dependency readiness        are all hard dependencies Architect-accepted?
scope                       does the delta match the Work Item contract?
authority ownership         does each authority have exactly one owner?
authority duplication       is any second authority introduced?
minting authority           who can create the authoritative instances?
mutation ownership          who may mutate each state?
provenance                  do claims carry their true source?
replay safety               are operations idempotent / replay-safe?
failure semantics           are failure paths explicit and tested?
cleanup                     are resources/paths released correctly?
recovery                    is recovery deterministic and tested?
adapter boundaries          does core stay free of vendor/access leakage?
vendor leakage              (import discipline, per LOCK-016/017)
architecture locks          LOCK-001 … LOCK-025 compliance
verification discrimination do tests prove the lock, not just exercise code?
evidence class              SOFTWARE / PHYSICAL / OPERATIONAL kept distinct
downstream impact           effects on dependents and the DAG
undocumented assumptions    anything the implementation assumes silently
```

A review that cannot evaluate a dimension must say so explicitly rather than
silently skipping it.

## 2. Evidence-class discipline (verification discrimination)

- A reference implementation, simulator, conformance peer, or test double
  satisfies only the verification surface explicitly assigned to it.
- SOFTWARE evidence never satisfies a PHYSICAL criterion; an unavailable
  environment yields NOT-TESTABLE, never PASS.
- An open external-evidence gate must remain visibly open in
  `spec/architect/evidence-obligations.yaml`; it cannot be closed by
  inference, by redefinition of "real", or by substituting an in-repo
  simulator (`spec/workflow.md` §2.2).
- Anti-promotion controls in accepted implementations (e.g. evidence-status
  surfaces that refuse software-to-physical promotion) must never be
  weakened.

## 3. Authorization and provenance rules

1. **No authorization, no implementation.** A PR containing implementation
   changes is reviewable only if the Work Item is covered by a
   repository-local authorization (`spec/architect/authorizations/`,
   `status: active`) that was present on `main` before the PR branched,
   declares the exact recorded baseline, and covers the PR delta in its
   scope. An **in-review ledger entry is descriptive only — it records
   what was delivered for review and never authorizes anything** (PA-001,
   `DEC-0045`). CI check `ARCH-08` (provenance mode) enforces this
   mechanically; the reviewer verifies the authorization was **inherited
   from `main`**, not introduced or modified by the PR itself
   (self-authorization).
2. **Implementation PRs must not modify `spec/architect/`.** The Architect
   owns the persistent state. Verdicts, ledger transitions, decision records,
   and authorizations are persisted by the Architect, not by the
   implementation PR under review.
3. **Chat designations are not durable authority.** Any pre-package or
   chat-issued designation must be re-anchored by a repository-local
   authorization record before further implementation proceeds.

## 4. Review verdicts

A review renders exactly one verdict per round:

```text
ACCEPTED            definition of done satisfied; acceptance recorded
CHANGES REQUIRED    blockers and required corrections listed; PR stays open
REJECTED            the approach is architecturally wrong; redo required
PROPOSED            a proposal awaiting review (ACRs, governance changes)
```

Each verdict must identify the exact reviewed SHA (the PR head under review).

## 5. Persistence requirement (the decision gate)

A review result **must be persisted before it can govern future work**:

1. The verdict is recorded as a decision record
   (`spec/architect/decisions/DEC-NNNN-*.yaml`) referencing the reviewed SHA.
2. The execution ledger transitions for the Work Item
   (`implemented → verified → in-review → accepted-merged`, or back for
   corrections) are updated in the same governance change.
3. Evidence obligations touched by the verdict are updated in
   `spec/architect/evidence-obligations.yaml` — never closed by inference.
4. Acceptance additionally requires: the merge SHA recorded in the ledger,
   the acceptance decision's `reviewed_sha` equal to the ledger's reviewed
   head, and the external-evidence status stated explicitly per
   `spec/workflow.md` §6.
5. Only after 1–4 merge to `main` may the acceptance unblock dependent Work
   Items.

A chat-only verdict has no durable effect. The GitHub PR conversation is the
review venue, but the repository artifact is the authority.

## 6. Governance PRs and ACRs

- Governance PRs (process documents, tooling, this package) are reviewed
  under the same dimensions where applicable; scope and
  frozen-document integrity dominate.
- ACRs are reviewed against the eight required elements of
  `spec/change-control.md` §3; approval is never implied by silence,
  inaction, or a passing CI run.
- A governance improvement that would change frozen architecture must be
  stopped and converted into an ACR.

## 7. Self-merge prohibition

Z.ai must never merge its own PR (workflow.md §6). The Architect merges.
The persistent ledger records the merge SHA at merge time.
