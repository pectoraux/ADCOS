"""WORK-040 pilot deployment: the end-to-end ADCOS pilot.

The pilot family is DEPLOYMENT/CONTROL code: it composes the accepted
production families (WORK-003 .. WORK-039) exclusively through their
public contracts to execute a real multi-process deployment on the
actual host -- real OS processes, real TCP carriages, real sessions,
real local services, real relay carriage, and a real failure
transition -- and reports the honest three-class evidence with the
anti-promotion rules enforced in code.

The pilot NEVER carries protocol authority: no second
identity/session/routing/policy/federation authority exists here, and
no simulated evidence is ever promoted to a physical claim.
"""

from . import deployment, evidence, fabric, marshal, physical, platform, topology, wire
from .deployment import (
    NodeJournal,
    run_appliance_node,
    run_device_node,
    run_pilot_deployment,
    run_relay_node,
)
from .errors import PilotError, PilotReasonCode
from .evidence import (
    PHYSICAL_DEVICE_OBLIGATION,
    REAL_5G_OBLIGATION,
    attach_evidence,
    criterion_outcome_for_5g,
    evidence_statement,
    pilot_report_document,
    record_execution,
)
from .model import (
    CriterionId,
    CriterionOutcome,
    CriterionStatus,
    ExecutionRecord,
    PilotCheck,
    PilotEvent,
    PilotEventKind,
    PilotEvidenceClass,
    PilotRunResult,
    PILOT_CRITERIA,
    PILOT_HARNESS_VERSION,
    pilot_event_list_digest,
    sha256_hex_of_bytes,
)

__all__ = [
    # errors
    "PilotError",
    "PilotReasonCode",
    # model
    "PilotEventKind",
    "PilotEvent",
    "pilot_event_list_digest",
    "CriterionId",
    "CriterionStatus",
    "PilotEvidenceClass",
    "CriterionOutcome",
    "ExecutionRecord",
    "PilotCheck",
    "PilotRunResult",
    "PILOT_HARNESS_VERSION",
    "PILOT_CRITERIA",
    "sha256_hex_of_bytes",
    # submodules (frozen __all__ on each)
    "marshal",
    "wire",
    "topology",
    "fabric",
    "platform",
    "deployment",
    "evidence",
    "physical",
    # deployment
    "run_pilot_deployment",
    "run_appliance_node",
    "run_relay_node",
    "run_device_node",
    "NodeJournal",
    # evidence
    "record_execution",
    "criterion_outcome_for_5g",
    "attach_evidence",
    "evidence_statement",
    "pilot_report_document",
    "PHYSICAL_DEVICE_OBLIGATION",
    "REAL_5G_OBLIGATION",
]
