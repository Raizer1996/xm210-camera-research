# iCSee credential-generation RNG — static analysis result

**Target:** iCSee `com.xm.csee` v7.9.5_G (versionCode 79531)
**APK (base):** `apk/icsee_apkpure.apk` sha256 `cf79fbfe176b6013240b5d15c629a84ca4d985291044ec8bbddef9940d8602e9` (source: APKPure, XAPK split build; native libs from `config.arm64_v8a.apk`)
**Tools:** jadx 1.5.6 (Dex→Java), Ghidra 12.1.4 headless (arm64 native)
**Date:** 2026-10-23
**Scope:** static only, own hardware.

## Question
Does the credential-generation routine use `java.util.Random` (predictable) or `SecureRandom`?

## Answer
**`java.util.Random` — predictable. Not `SecureRandom`.**
The app-side generator is `org.apache.commons.lang3.RandomStringUtils.randomAlphanumeric()`, which in the bundled (pre-3.16) build is backed by a single static `java.util.Random`.

## Two distinct credential-generation points

### 1. App-side — WiFi/AP ("quick config") pairing  ← this is the Java generator
During pairing the app generates a **new** admin account and pushes it to the camera with the
`ChangeRandomUser` config (DVRIP cmd 1660):

- `NewName = RandomStringUtils.randomAlphanumeric(8)`  (8-char alphanumeric user)
- `NewPwd  = RandomStringUtils.randomAlphanumeric(16)` (16-char alphanumeric password)

Call sites (decompiled, obfuscated):
- `com/xworld/activity/adddevice/QuickConfigResultActivity.java:1437-1461`
- `com/xworld/activity/adddevice/SearchDevActivity.java:568-592`
- `com/xworld/activity/adddevice/Add4GDeviceByBlueToothActivity.java` / `AddDeviceByBlueToothActivity.java` (same `ChangeRandomUser` shape)

The RNG, from the bundled `org/apache/commons/lang3/RandomStringUtils.java` (Apache-2.0, quoted):
```java
import java.util.Random;                            // line 3
private static final Random RANDOM = new Random();  // line 8
public static String randomAlphanumeric(int i10) {  // line 18
    return random(i10, true, true);
}
public static String random(int i10,int i11,int i12,boolean z9,boolean z10){   // line 34
    return random(i10,i11,i12,z9,z10,null,RANDOM);                             // uses static RANDOM
}
public static String random(...,Random random){                               // line 42
    ... cNextInt = (char)(random.nextInt(i13) + i11); ...                      // line 63
}
```
`new Random()` = `java.util.Random`, a 48-bit LCG seeded from a time-derived value at class
load. `randomAlphanumeric` → shared static `RANDOM.nextInt()`. 0 occurrences of `SecureRandom`
in the class. (commons-lang3 only added secure `RandomStringUtils.secure()/secureStrong()` in
3.16.0; this build predates/omits it.)

### 2. Device-side — `GetRandomUserInfo`  ← NOT the app
The app can also **request** a random account from the camera and only reads/stores it:
- `com/xworld/devset/DevAboutSettingActivity.java:470` sends `GetRandomUserInfo` (cmd 1020).
- `:1209-1211` parses the device response `GetRandomUserInfo{UserName,Password}` and caches it.
Here the RNG lives in the **camera firmware**, not the APK, and cannot be answered from the app.

## What the native lib does (and does not)
`libFunSDK.so` (arm64) exports the cred JNI funcs, but they are **not** generators:
- `Java_com_lib_FunSDK_DevGetLocalPwd/UserName` → `CDataCenter::GetDevPwd/GetDevLoginUser`:
  read a per-device value from a key store and **AES-ECB-Base64 decrypt** it
  (`GetLocalPwdAesKey`, key at `CDataCenter+0x808`); empty → `""` → caller falls back to `admin`.
- `Java_com_lib_FunSDK_DevSetLocalPwd` → `DevSetLocalUserNameAndPwd` → `SetPwdToLocPwdDBFile`:
  **receives** user+pwd and AES-stores them. Values come from the caller (user input or §1/§2).
- `GenPWDToken` = deterministic AES/MD5/SHA1PRNG-key derivation (a token), no RNG.
No `rand/srand/random/arc4random/getentropy` in the cred call tree (Ghidra, 100+ funcs traced).
(SDK build path leaked in logs: `/Users/yuanxiaotian/.../funsdk/FunSDK/FunSDK.cpp`.)

## Classification impact
- App-generated creds (§1) → **CWE-338 (cryptographically weak PRNG)**. Stronger than the filed
  CWE-521: the 8/16-char length does NOT save it — `java.util.Random`'s 48-bit, time-seeded state
  is brute-forceable, and `nextInt` outputs leak LCG state, so an attacker who knows the approximate
  pairing timestamp can reconstruct both NewName and NewPwd regardless of length.
- The 4-char `[a-z]` / 6-char `[a-z0-9]` creds in filed finding #4 do **not** match §1's 8/16-char
  output. They are consistent with the **device-side** default random user (§2), i.e. firmware RNG —
  a separate issue (short length → CWE-521), not the app.

## Caveats / next step
- Exact commons-lang3 version not recoverable (R8-stripped metadata); the decompiled class is
  unambiguous regardless.
- To pin the 4/6-char generator's RNG, extract the **XM210 firmware** and disassemble its
  random-user routine — that is device-side, outside the APK.

---

# Device-side RNG attempt — firmware analysis (2026-10-23)

**Goal:** disassemble the camera's `GetRandomUserInfo` handler to pin the 4/6-char cred RNG.

**Firmware obtained (exact match):** `IPC_XM210_X2P-WR-T_S38_WIFI.Q35343 V5.00.R02` (build 20260622),
via OpenIPC `xmupdates` catalog → Xiongmai OBS. File `000999Y0.1...zip`
sha256 `c0b3fc8d3af4a870f375e0c89fc09e30f0a8e034d9e42e561472ae404d2eec4c`.
Confirms device: `Hardware IPC_XM210_X2-WR-T_S38`, SoC XM530 family, WifiDriver ssv6158m.

**Unpacked (all on Windows, pure-Python — no binwalk/cramfs tools needed):**
- `General_...all.bin` is a ZIP → `u-boot.bin.img`, `u-boot.env.img`, `download.img`,
  `custom-x.cramfs.img`, `InstallDesc`.
- `custom-x.cramfs.img` = uImage(name=custom) → **cramfs LE**, extracted fully
  (`firmware/xm210_wifi/extracted/rootfs`). Contents: fonts, audio prompts, PTZ `.nut`
  scripts, strings, configs. **No app binary, no RNG.**
- `download.img` = uImage(firmware) → nested uImage(name=`app`) → **payload entropy 7.997
  bits/byte = AES-encrypted.** No cramfs/squashfs/ELF/gzip magic anywhere. The Sofia/main
  DVRIP binary (which owns `GetRandomUserInfo`) lives here, **encrypted**.
- `u-boot.bin.img` is only the **SPL** (`spl 2024.11`, 8 KB): "Upgrader App From Download",
  "Decode Err" — decrypts/verifies the app image but does not carry the key in cleartext.
- `InstallDesc` has an RSA-ish `Mx8Q` signature field, consistent with signed+encrypted images.

**Wall:** XM V5.00 encrypts the app partition. No public XM530 app-image decryptor exists
(OpenIPC/thingino *replace* the firmware, they don't decrypt XM's). Flash dump wouldn't help —
flash stores the same encrypted blob; it's decrypted into RAM at boot.

**Remaining route to the decrypted Sofia (device-side RNG):**
- **UART root shell on the live camera** (recommended): XM530 exposes a serial console
  (115200 8N1). With a ~$2 USB-TTL adapter on GND/TX/RX, interrupt u-boot or get the shell,
  then copy the already-decrypted `Sofia`/app binary from the running rootfs and pull it off.
  Then Ghidra (arm) → `GetRandomUserInfo` → RNG. Much lighter than a flash dump.
- Alternatives: extract the XM AES key from the full bootloader/SoC (deep, uncertain).

**Net:** app-side RNG = answered (`java.util.Random`, CWE-338). Device-side 4/6-char RNG =
blocked at firmware encryption; needs a UART shell on a live XM210.

---

# Live device confirmation (2026-10-23) — using findings #1 + #4

**Camera:** `<device-ip>:34567` (DVRIP only; RTSP/web/telnet closed). PID `<device-pid>`,
MAC `<device-mac>`. Found via active ping-sweep (first attempt only read stale ARP; `.128`
was my own Wi-Fi adapter).

**Finding #1 (pre-auth disclosure) — works:** DVRIP opcode **1472**, SessionID=0, empty body →
returns the admin user record with no auth:
`Name="<REDACTED-user>", Group="admin", Password="<REDACTED-xmhash>", PasswordV2=..., Deraup=...`
(Opcode 1470 similarly leaks the AuthorityList pre-auth.)

**Auth without cracking:** XM DVRIP logs in with the *stored hash itself*. Replaying
`UserName=<REDACTED-user>, PassWord=<REDACTED-xmhash>` → `Ret=100`, session granted, AdminToken issued.

**Finding #4 — confirmed live and exactly:** authenticated `GetRandomUserInfo` (cmd 1020) returns
the device's own random account in **plaintext**:
`{"UserName":"<REDACTED-user>","Password":"<REDACTED-pass>"}`
- `<REDACTED-user>`  = 4-char `[a-z]`  ✓
- `<REDACTED-pass>` = 6-char `[a-z0-9]` ✓  (~31 bits)
- This is a **device command returning the device's generated account** → the 4/6-char cred is
  **device-firmware-generated**, as predicted (not the iCSee app). Confirms the §2 split.

**Hash loop closed:** XM 8-char hash (hashcat mode 22401) of `<REDACTED-pass>` = `<REDACTED-xmhash>` = the disclosed
hash. `xm_hash = md5(pw); for i in 8: c=(m[2i]+m[2i+1])%62 -> [0-9A-Za-z]`. Weak + non-salted.

**Still open — the device RNG *primitive*:** the generator code lives in the encrypted `Sofia`
app binary. DVRIP exposes no telnet and no file-read, so the binary needs a shell. `Uart.Comm`
confirms a **115200 8N1 UART console** — the clean route: UART shell → copy decrypted `Sofia`
from the running rootfs → Ghidra(arm) → `GetRandomUserInfo` generator → rand vs CSPRNG.

NOTE: device creds above are live research data for an owned device — do NOT commit to the public repo.

---

# No-hardware shell attempts (2026-10-23) — authenticated DVRIP

Goal: get a shell / the decrypted Sofia over the network (no UART).

- **File-read via playback/log API** — dead: camera has **no SD/storage** (`OPFileQuery`/`OPLogQuery`
  return Ret:119), so the file API is empty.
- **Authenticated command-injection RCE** (as admin `<REDACTED-user>`, hash-replay login):
  - **NTP** (`NetWork.NetNTP` server fields) — set OK (Ret:100), periodic sync fired, **no exec**.
  - **Email** (`OPMailTest` SmtpServer, msgid 1450) — test ran (Ret:100), **no exec / no connect-back**.
  - **DDNS** (`OPDDNSTest` host/server) — ran (Ret:100), **no exec**.
  Payloads: `;telnetd -p2323 -l/bin/sh;` + wget connect-back canary; neither popped 2323 nor hit
  the listener. → This 2026 build (V5.00.R02) uses real NTP/SMTP/DDNS clients, **not `system()`** —
  **hardened against the classic XM authenticated config-injection RCEs.**
- Device left clean (NTP config restored; mail/DDNS "test" actions don't persist).

**Conclusion:** no-hardware routes to the decrypted `Sofia` are exhausted on this firmware
(file-read needs storage; firmware app partition is AES-encrypted with no public key; authenticated
config-injection is patched; memory-corruption/CVE paths need the binary or a closed port). The
device-side RNG *primitive* realistically requires **UART** (115200 8N1, confirmed) to read the
running decrypted binary. Everything else about finding #4 is already confirmed live.

---

# Device-side RNG — firmware decompression + analysis (2026-10-23) — SUCCESS (offline)

Routes: user authorized "both heavy routes"; no UART adapter. Firmware-decryption pursued (safe/offline).

## The firmware is NOT encrypted — it's LZMA-packed
- `download.img` → nested uImage `app` → high-entropy blob (7.997 b/B) that looked encrypted.
- **No AES/SHA constant tables** anywhere (SPL or blob) → ruled out encryption.
- The SPL (`u-boot.bin.img`) is **T-Head RISC-V** (`csi_mpu_config_region`); its decode routine
  `FUN_0000135a` is an **LZMA range decoder** (range<<8 renorm, (range>>11)*prob 11-bit model).
- The blob's 16-byte header is a standard **`.lzma` (alone)** header: props `0x00` (lc0/lp0/pb0),
  uncompressed size `0x37f40a` = 3,666,954 — matched exactly. Decompressed with pyliblzma
  FORMAT_RAW from offset 13 → `app_dec.bin` (3.67 MB, RISC-V image).

## Decompressed image contents (RISC-V RV32GC, T-Head; load base 0x4004000)
Contains `Sofia`, `GetRandomUserInfo`, the random-password management code
(`RecoverRandom`, `Deraup`, "recover random password", "--new year, delete old password"),
the 62-char base alphabet, and **`/dev/urandom`** with an **" ENTROPY test: /dev/urandom"** string
in `JFTSDK init`.

## RNG verdict (device side)
- The firmware's **sole randomness primitive** is `FUN_040f8dac` = a clean
  **`/dev/urandom` reader** (`fopen("/dev/urandom")` → `fread(buf,1,len)` → `fclose`).
- **No `rand()`/`srand()`/`random()` PRNG** backs credential generation (the only `rand`
  occurrences are AES-nonce debug logging). **No `srand(time(...))` time-seeding.**
- ⇒ **Device-side RNG is a CSPRNG (`/dev/urandom`)** — high confidence from: the dedicated
  urandom reader, the explicit SDK entropy test on `/dev/urandom`, and the absence of any PRNG.
  Caveat: the exact cred-generator→reader call chain could **not** be fully traced statically —
  Ghidra's RISC-V analysis can't follow this T-Head image (custom insns) and the reader is
  dispatched indirectly (no JAL/auipc+jalr/stored-pointer callers resolvable). A UART shell could
  confirm the last link, but all positive evidence points to `/dev/urandom`.

## Net classification (both sides resolved)
| Side | Who generates | Length | RNG | CWE |
|------|---------------|--------|-----|-----|
| **App** (iCSee pairing, `ChangeRandomUser`) | the Android app | 8 / 16 alnum | `java.util.Random` (predictable) | **CWE-338** |
| **Device** (firmware, `GetRandomUserInfo`) | camera firmware | 4 `[a-z]` / 6 `[a-z0-9]` | `/dev/urandom` (CSPRNG) | **CWE-521** (short length only) |

So filed finding #4 (CWE-521) is correct **for the device-generated creds**, and the *app* path is a
distinct, stronger issue (CWE-338). Live device confirmed the 4/6-char output (`<REDACTED-user>`/`<REDACTED-pass>`).

Memory-corruption route not pursued: the firmware route answered the RNG question, and fuzzing the
live camera risks bricking for no additional answer.
