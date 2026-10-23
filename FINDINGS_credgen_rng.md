# Credential generation — technical analysis (supporting Finding #4 / Finding #5)

**Researcher:** Artyom Bordulev ([@Raizer1996](https://github.com/Raizer1996))
**Scope:** static analysis of the iCSee application package; cross-referenced against the device's
own observable DVRIP responses. No firmware extraction, no device code execution.

## Objective

Determine where the camera's administrator credentials are generated, by which component, and with
what quality of randomness — resolving an ambiguity in Finding #4 between *application* and
*device/firmware* responsibility.

## Result

There are **two distinct credential-generation points**, with different root causes:

| | Component | Credential | Entropy source | Weakness | CWE |
|---|---|---|---|---|---|
| A | **Device / firmware** | 4-char `[a-z]` user + 6-char `[a-z0-9]` password | device-resident generator | insufficient length (~31 bits) | **CWE-521** |
| B | **iCSee application** | 8-char + 16-char alphanumeric (provisioning) | `java.util.Random` (predictable) | predictable PRNG | **CWE-338** |

Finding #4 as originally filed conflated these. Corrected: **#4 → device (A, CWE-521)**;
**#5 → application (B, CWE-338)**.

## A. Device-side credential (Finding #4)

The device generates its own administrator account. The application **reads** it via the DVRIP
`GetRandomUserInfo` request; it does not create it. The account follows a fixed short format
(4-character lowercase username, 6-character lowercase-alphanumeric password ≈ 31 bits), and the
stored password hash is the weak, unsalted Xiongmai scheme (recoverable with hashcat mode 22401).
The weakness here is **insufficient credential length** — independent of the quality of the RNG,
and classified **CWE-521**.

The device generator's underlying RNG primitive was **not** assessed within this report's scope
(that would require firmware or on-device analysis, which was not performed here).

## B. Application-side credential (Finding #5)

During Wi-Fi / AP provisioning the application generates a **new** administrator account and
provisions it onto the device. The generator is
`org.apache.commons.lang3.RandomStringUtils.randomAlphanumeric(8)` (username) and `(16)` (password),
observed in the add-device provisioning activities.

The bundled `RandomStringUtils` is backed by a shared static `java.util.Random`:

```java
import java.util.Random;
private static final Random RANDOM = new Random();   // 48-bit LCG — not a CSPRNG
public static String randomAlphanumeric(int n) { ... RANDOM.nextInt(...) ... }
```

`java.util.Random` is a 48-bit linear congruential generator whose state is recoverable from a few
observed outputs; subsequent outputs are then predictable. The 8/16-character length does not
compensate, because predictability is a property of the generator, not the length. This is the
distinct, application-side weakness (**CWE-338**) detailed in advisory XM210-2026-005.

## Reproducibility

- Application: `com.xm.csee` 7.9.5_G, SHA-256
  `cf79fbfe176b6013240b5d15c629a84ca4d985291044ec8bbddef9940d8602e9`.
- Decompile the APK (e.g. jadx) and inspect `org/apache/commons/lang3/RandomStringUtils.java` and
  the `ChangeRandomUser` flow in the add-device activities.
- The device-side credential format (A) is observable in the device's `GetRandomUserInfo` response.

## Remediation

- Application: use a CSPRNG (`RandomStringUtils.secure()` / `SecureRandom`); do not share a
  `java.util.Random` for security tokens.
- Device/firmware: increase generated credential length and entropy; replace the weak password hash.
