# R2 System Composition Design Note

This is a governance-only planning artifact for the post-R1 composition gate. It does not authorize implementation.

The mission-critical product is the composed developer path, not another isolated subsystem. The composition must expose one coherent control-plane journey across already accepted authorities: application intent, commercial offer and lease, eligibility, candidate selection, NetworkPath validation, containment, session, delivered usage, billable finality, allocation, external payment-provider reference, reconciliation, recovery, and canonical API/webhook status.

The conformance target is authority composition, not authority duplication. Each existing authority retains ownership of its canonical state, while WORK-054 provides only the composition seam and deterministic evidence needed to prove the complete journey.
