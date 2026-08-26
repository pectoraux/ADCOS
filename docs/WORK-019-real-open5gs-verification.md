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

## External observation acceptance run

The observe-then-adopt gate was run against the already-running stack with:

```text
OPEN5GS_INTEROP=1
OPEN5GS_PEER_KIND=real_open5gs
OPEN5GS_SBI_URL=http://127.0.0.4:7777
OPEN5GS_PDU_SESSION_ID=1
```

Independent fixture evidence was present:

- UERANSIM completed real 5G-AKA registration.
- Open5GS logged `Number of UPF-Sessions is now 1`.
- UERANSIM established PDU session PSI 1 and brought up
  `uesimtun0` at `10.45.0.4`.

The adapter observation request reached the real Open5GS SMF over HTTP/2, but
Open5GS rejected `GET /nsmf-pdusession/v1/sm-contexts/1`:

```text
HTTP 400
{"title":"Invalid HTTP method","detail":"GET","instance":"/sm-contexts/1"}
```

The Open5GS SMF implementation supports POST create/modify/release handling
for this resource, not retrieval. This confirmed that SMF SBI was the wrong
observation surface; the correction below uses Open5GS's supported info API.

## `/pdu-info` observation correction

Open5GS's supported vendor-specific observation surface is the metrics info
API, not SMF SBI retrieval. With `OPEN5GS_INFO_URL=http://127.0.0.4:9090`,
the adapter successfully observed the live fixture from `GET /pdu-info`:

```text
SUPI: imsi-999700000000001
PSI: 1
DNN: internet
S-NSSAI: SST 1 / SD ffffff
UE IPv4: 10.45.0.4
PDU state: active
```

The manager then accepted the exact adapter-produced observation and created
the ADCOS session-to-external-PDU binding. This proves the authoritative
observe -> adopt path against real Open5GS/UERANSIM state.

The final application payload leg remains blocked in this fixture run because
Open5GS does not expose a TCP `data_endpoint`; the user plane is the real
UE TUN -> N3 GTP-U -> UPF -> data-network path. A DN echo service reachable
through the configured UPF route (and `OPEN5GS_DATA_PEER` only as the test
application endpoint) is still required to capture byte-identical return
payload evidence.

An attempted independent DN endpoint was started at Docker address
`172.17.0.3:5555`. The policy route correctly selected `uesimtun0` for
traffic from `10.45.0.4` to that address, but the real ADCOS socket timed out
and the DN endpoint received no connection. The gate returned
`DATA_PEER_UNREACHABLE`; it did not infer UPF traversal from a configured
TCP destination. Host packet capture was unavailable without capture
capability (`tcpdump: Operation not permitted`), so no `[UPF]` or `[IP]`
payload proof is claimed.

## N6/DN topology correction run

The DN endpoint was placed on the host address used by the Open5GS
host-network deployment (`192.168.100.20:5556`), rather than an unrelated
Docker bridge. The policy route for traffic from `10.45.0.4` selected
`uesimtun0`. The live observe -> adopt gate returned `PASSED` with a
byte-identical 36-byte payload, and the DN echo server independently logged:

```text
accepted=('10.45.0.4', <ephemeral-port>)
payload=b'adcospktpath-real-open5gs-interop-v1'
```

This proves the DN received the payload with the externally established UE
source address and that the application received the exact return bytes.
The environment did not permit packet capture, so an independent `[UPF]`
interface capture is still outstanding; the run does not claim captured
GTP-U/N3 proof.

The PASS record includes the required provenance fields:

```text
[PDU] external PDU session ID: 1; Open5GS pdu_state: active
[UE]  address: 10.45.0.4
[ROUTE] selected interface: uesimtun0
[DN]   endpoint: 192.168.100.20:5556; source observed: 10.45.0.4
[IP]   payload length: 36; payload equality: true
[IP]   payload SHA-256: emitted by InteropOutcome.payload_sha256
```

The gate now emits these fields structurally in `InteropOutcome`, so a PASS
cannot be mistaken for a generic TCP echo result.
