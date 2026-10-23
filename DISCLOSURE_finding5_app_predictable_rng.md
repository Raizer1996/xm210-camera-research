# Finding #5 — iCSee Android app generates device admin credentials with a predictable PRNG (`java.util.Random`)

**Researcher:** Artyom Bordulev (GitHub @Raizer1996)
**Status:** draft for coordinated disclosure — **new finding ⇒ new CVE request** (does not amend the already-filed CAN-2026-2037011/2037013/2037014).
**Date:** 2026-10-23
**Class:** CWE-338 (Use of Cryptographically Weak PRNG)
**Component:** iCSee Android app `com.xm.csee`, version **7.9.5_G** (versionCode 79531). Bundled `org.apache.commons.lang3.RandomStringUtils` (pre-3.16 insecure variant).

---

## Summary

During Wi-Fi / AP ("quick config") pairing, the iCSee app **generates a new device administrator
account** (username + password) and provisions it onto the camera via the DVRIP `ChangeRandomUser`
command. The generator is `org.apache.commons.lang3.RandomStringUtils.randomAlphanumeric()`, which
in the bundled build is backed by a single static **`java.util.Random`** — a 48-bit linear
congruential generator, not a CSPRNG. Its internal state is recoverable from a small number of
outputs, after which all generated credentials are predictable. An attacker who can observe or
derive any output of this generator can reconstruct the admin password that the app sets on the
device, yielding full administrative control.

## Affected flow

Pairing (`com.xworld.activity.adddevice.*`) builds the `ChangeRandomUser` request with
app-generated credentials:

```
NewName = RandomStringUtils.randomAlphanumeric(8);    // 8-char alphanumeric username
NewPwd  = RandomStringUtils.randomAlphanumeric(16);   // 16-char alphanumeric password
// -> JSON {"ChangeRandomUser":{"RandomName":<old>,"RandomPwd":<old>,"NewName":<new>,"NewPwd":<new>}}
// -> FunSDK.DevConfigJsonNotLoginPtl(..., "ChangeRandomUser", ..., 1660, ...)   // DVRIP cmd 1660
```

Observed call sites (decompiled, ProGuard-obfuscated):
- `com/xworld/activity/adddevice/QuickConfigResultActivity.java:1437-1461`
- `com/xworld/activity/adddevice/SearchDevActivity.java:568-592`
- `com/xworld/activity/adddevice/Add4GDeviceByBlueToothActivity.java`, `AddDeviceByBlueToothActivity.java`

## Root cause

Bundled `org/apache/commons/lang3/RandomStringUtils.java` (Apache-2.0; critical lines quoted):

```java
import java.util.Random;                            // line 3
private static final Random RANDOM = new Random();  // line 8  — java.util.Random, shared static
public static String randomAlphanumeric(int n){ return random(n, true, true); }      // line 18
public static String random(...){ return random(..., RANDOM); }                       // line 34
public static String random(...,Random random){ ... random.nextInt(i13) ... }         // line 63
```

- `new Random()` = `java.util.Random`, a 48-bit LCG. Zero occurrences of `SecureRandom` in the class.
- `java.util.Random`'s 48-bit state is fully recoverable from two consecutive 32-bit `nextInt`
  outputs; thereafter every past/future output is deterministic. The static `RANDOM` is shared
  across *all* `RandomStringUtils` uses in the app, widening the observation surface.
- `new Random()` seeding (`seedUniquifier() ^ System.nanoTime()`) is itself low-entropy and, in some
  conditions, brute-forceable.

The 8/16-char length does **not** mitigate this: predictability is a property of the RNG, not the
output length. (Apache Commons Lang only added secure `RandomStringUtils.secure()/secureStrong()`
in 3.16.0; this build predates/omits it.)

## Impact

An attacker who recovers the generator state — e.g., by observing any `RandomStringUtils` output
from the app, or the provisioning traffic during setup — can predict the `NewPwd` set as the device
admin password, then authenticate to the camera (DVRIP / cloud) as administrator: full video access,
configuration, and persistence. Severity is comparable to the previously filed credential finding;
this one is a *predictable-RNG* weakness rather than a short-length one.

**CVSS v3.1 (estimate):** `AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` → **Base 7.0 (High)**

Rationale / exploitability caveat: `java.util.Random` is a 48-bit LCG whose internal state is
recoverable from ~2 observed 32-bit outputs, after which all outputs are predictable — but the
attacker must **observe at least one output**, realistically by being on the local Wi-Fi during
pairing (hence **AV:A**, **AC:H**). A concrete *remote* output-leak has not been demonstrated; if one
exists, the vector rises to `AV:N` (Base 8.1). Blind seed brute-force (`new Random()` ≈
`seedUniquifier() ^ System.nanoTime()`) is situational, not reliable. Impact is C:H/I:H/A:H because a
predicted `NewPwd` grants device administrator access.

## Remediation

- App: replace the insecure static generator with a CSPRNG — `RandomStringUtils.secure()`
  (commons-lang3 ≥ 3.16) or a `java.security.SecureRandom`-backed generator. Do not reuse a shared
  `java.util.Random` for security tokens.
- Treat the generated admin password as a secret in transit (it is provisioned over DVRIP).

---

## Attribution correction to Finding #4

Finding #4 as filed states *"iCSee generates weak admin creds — 4-char [a-z] username + 6-char
[a-z0-9] password."* Static analysis of the app **and** the device firmware shows this conflates two
separate credential-generation points:

1. **Device-firmware-generated (the 4/6-char creds).** The 4-char `[a-z]` username + 6-char
   `[a-z0-9]` password are generated by the **camera firmware**, not the app. The app merely
   **requests** them via DVRIP `GetRandomUserInfo` (cmd 1020) and caches them locally. Confirmed live
   on the device: `GetRandomUserInfo → {"UserName":"<REDACTED-user>","Password":"<REDACTED-pass>"}`. Firmware analysis
   (XM210 V5.00.R02, decompressed from the vendor image — LZMA-packed, not encrypted) shows the only
   randomness primitive is a **`/dev/urandom` reader** (CSPRNG); no `rand()`/`srand(time)` PRNG backs
   it. So the 4/6-char weakness is a **short-length** issue (**CWE-521**, ~31 bits) attributable to
   the **firmware**, not a predictable-RNG issue, and not the app.

2. **App-generated (this Finding #5).** Separately, during pairing the **app** generates its own
   8/16-char admin account with a **predictable PRNG** (`java.util.Random`, **CWE-338**).

Recommended re-statement: **Finding #4 → firmware, CWE-521 (short length)**;
**Finding #5 → app, CWE-338 (predictable PRNG).** Two distinct root causes, two distinct components.

## Evidence / reproducibility
- iCSee base APK `com.xm.csee` 7.9.5_G, sha256 `cf79fbfe176b6013240b5d15c629a84ca4d985291044ec8bbddef9940d8602e9`.
- Firmware `IPC_XM210_X2P-WR-T_S38_WIFI V5.00.R02` (OpenIPC xmupdates catalog → Xiongmai OBS),
  zip sha256 `c0b3fc8d3af4a870f375e0c89fc09e30f0a8e034d9e42e561472ae404d2eec4c`; decompressed
  RISC-V image `app_dec.bin` contains `Sofia`, `GetRandomUserInfo`, `/dev/urandom`.
- Live device confirmation and the pre-auth disclosure (Finding #1, DVRIP opcode 1472, SessionID=0)
  independently recovered the device admin account.
- Full method log: `FINDINGS_credgen_rng.md`.

*Boundary: device credentials and the user's own network details recovered during testing are not
included here and must not be committed to the public repository.*
