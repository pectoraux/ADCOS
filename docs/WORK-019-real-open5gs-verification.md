# WORK-019 real Open5GS verification

## Run metadata

- ADCOS commit: `d9b1c0356367320236b5b78f8441530e292e59a6`
- Host OS: Ubuntu 25.04
- Kernel: Linux 6.14.0-37-generic x86_64
- Open5GS source: upstream commit `d261bd43d859ec3d9c9f95a441dc295ce0814a7b`
- UERANSIM source: upstream commit `c0b2b5933f1e678b0fbe8a00fc27e9d06c5fd1591658e2745689e084e36f7f0d`

## Environment provisioned

- Open5GS was built from upstream source in Docker image
  `tetevi/ubuntu-latest-open5gs-build`.
- MongoDB 8.0 was started in container `open5gs-mongodb`; `db.runCommand({ping:1})`
  returned `{ ok: 1 }`.
- Open5GS NRF, SCP, AMF, SMF, UPF, AUSF, UDM, UDR, PCF, NSSF, and BSF
  processes were started in privileged host-network container `open5gs-core`.
- UERANSIM `nr-gnb` and `nr-ue` binaries were built successfully.
- SCTP and `/dev/net/tun` were available.

## ADCOS verification

The deterministic FiveG Core selftest passed:

```text
Result: PASS (31/31 cases)
```

The real gate was run with:

```text
OPEN5GS_INTEROP=1
OPEN5GS_PEER_KIND=real_open5gs
OPEN5GS_SBI_URL=http://127.0.0.5:7777
OPEN5GS_DATA_PEER=127.0.0.1:5555
```

The gate reached the real Open5GS AMF SBI listener and failed honestly during
subscriber provisioning:

```text
Open5GS interop SBI_FAILED:
provision_subscriber (POST /nudm-uecm) failed: nf-unavailable
```

Therefore no real UE registration, PDU session, UPF traversal, or end-to-end
IP payload evidence is claimed. The required `PASSED` result was not fabricated.

## Regression status

- `fivegc_selftest.py`: PASS (31/31)
- Other repository suites: 20 passed
- `ipintegration_selftest.py`: FAIL (44/45), existing
  `case_42_b3_real_ipv6_loopback_conformance` failure
- Frozen `spec/` diff: clean

## Review conclusion

```text
WORK-019 REAL INTEROPERABILITY = BLOCKED
```

The remaining blocker is compatibility between the current production-shaped
ADCOS SBI requests and the live Open5GS SBI/subscriber configuration. This
report contains no subscriber secrets, keys, passwords, or tokens.

## Follow-up correction

The adapter was corrected to use Open5GS's required HTTP/2 prior-knowledge
transport for explicitly enabled real runs and to use the UDM AMF-registration
operation shape. The deterministic conformance peer remains on HTTP/1.1.
The live run now reaches Open5GS over HTTP/2 but still returns an SBI failure;
subscriber database seeding and the complete UERANSIM-driven lifecycle remain
required before B1 can pass.

## Architect correction-cycle baseline

The external Open5GS/UERANSIM baseline was then established independently:

- A disposable subscriber was seeded in the external Open5GS MongoDB store.
- UERANSIM gNB completed NG setup over SCTP to the Open5GS AMF.
- UERANSIM UE completed real 5G-AKA registration.
- PDU session establishment succeeded with PSI 1.
- UERANSIM created `uesimtun0` with UE address `10.45.0.4`.

The ADCOS adapter was extended with an explicit `ue_source_address` fixture
option. When configured, its data socket binds to the externally established
UE address before connecting to the configured data-network peer, so routing
can traverse the UE TUN/UPF path rather than using an unbound host source.
This does not claim B1: the current contract still has no operation for
attaching an already-established external PDU session, and no end-to-end
ADCOS payload evidence was observed in this run.
