# Tenda AC8 V2 V02.03.01.90_multi `goform/setWifi` `wifiPwd` Stack-Based Buffer Overflow

## Summary

A stack-based buffer overflow vulnerability exists in the `goform/setWifi` HTTP endpoint of Tenda AC8 V2 firmware `V02.03.01.90_multi`. The `wifiPwd` parameter is not length-validated before being persisted to NVRAM. On subsequent read/use of this value, an unsanitized copy operation overflows a fixed-size stack buffer, overwriting the saved return address and allowing full control of the program counter (PC). Exploitation results in complete denial of service: the device becomes entirely unresponsive (no LAN, no Wi-Fi, no response to the hardware reset button) and requires low-level UART/flash recovery to restore.

- **Vendor:** Tenda
- **Product:** AC8
- **Hardware version:** V2
- **Firmware version:** V02.03.01.90_multi
- **Vulnerability class:** Stack-based Buffer Overflow
- **CWE:** CWE-121 (Stack-based Buffer Overflow), CWE-787 (Out-of-bounds Write), CWE-20 (Improper Input Validation)
- **Attack vector:** Network — standard HTTP POST to the device's admin interface (`goform/setWifi`). Exploitable from the LAN by default; exploitable remotely over the internet on any unit with WAN/remote management enabled, as the endpoint has no transport-layer restriction beyond normal HTTP(S) access to the management interface
- **Impact:** Denial of Service (persistent, requires hardware-level recovery); potential Remote Code Execution (PC/RA fully attacker-controlled)
- **CVSS 3.1:** AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H (CRITICAL)
- By default, there is no session cookies if the admin password was not initialized. With that reason, it can be unauthenticated. Can be AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
## Affected Component

- **Endpoint:** `POST /goform/setWifi`
- **Parameter:** `wifiPwd`
- **Underlying storage:** NVRAM (`Nvram` partition, flash offset `0x1f8000`, size `0x7fff`), mirrored to `Snvram` (flash offset `0x1f0000`, size `0x7fff`)
![](https://yzdhzjjwtsjwhabhuksf.supabase.co/storage/v1/object/public/assets/projects/Vuln_Research/AC8V2/nvram_sram.png)
## Technical Details

### Request
![](https://yzdhzjjwtsjwhabhuksf.supabase.co/storage/v1/object/public/assets/projects/Vuln_Research/AC8V2/request.png)

- An oversized value (observed: 315 bytes of `0x41` / `A`) is submitted in the `wifiPwd` field of the `setWifi` form submission:

- The device accepts the oversized value without any server-side rejection or truncation, and reports success:

- No input length validation is performed on `wifiPwd` prior to it being accepted and written to persistent configuration storage.

### Root Cause

1. The oversized `wifiPwd` string is accepted by the `goform/setWifi` handler with no bounds checking and persisted into the device's NVRAM configuration block.
2. The NVRAM integrity mechanism (MD5-checksummed) does not reject the oversized/corrupted entry at write time.
![](https://yzdhzjjwtsjwhabhuksf.supabase.co/storage/v1/object/public/assets/projects/Vuln_Research/AC8V2/md5.png)
3. On boot, when the stored configuration value is read and copied into a fixed-size stack buffer (consistent with an unsanitized `strcpy`/`sprintf`/`memcpy`-style call in the `wps`-related initialization path), the oversized value overflows the buffer, corrupting the saved stack frame including the return address.
![](https://yzdhzjjwtsjwhabhuksf.supabase.co/storage/v1/object/public/assets/projects/Vuln_Research/AC8V2/wps.png)
4. On function return, execution jumps to the attacker-controlled address, which is not a valid mapped address, triggering a TLB Miss exception and halting normal operation.
![](https://yzdhzjjwtsjwhabhuksf.supabase.co/storage/v1/object/public/assets/projects/Vuln_Research/AC8V2/TLB.png)

### Evidence of NVRAM Persistence and Corruption
![](https://yzdhzjjwtsjwhabhuksf.supabase.co/storage/v1/object/public/assets/projects/Vuln_Research/AC8V2/UART_.jpg)

Serial console boot log confirms the configuration storage layout and shows checksum verification failures on both the primary and mirrored NVRAM blocks following the oversized write:

![](https://yzdhzjjwtsjwhabhuksf.supabase.co/storage/v1/object/public/assets/projects/Vuln_Research/AC8V2/nvram_sram.png)

The computed MD5 (`md5`) does not match the stored/expected value (`org`) for both the `Nvram` and `Snvram` blocks, while the smaller `Envram` block (boot-critical values such as MAC address) passes its CRC check (`crc:72 org:72`) and remains unaffected. This indicates the overflow corrupted a significant portion of the main configuration block rather than only the targeted field.

### Evidence of Instruction Pointer Control

Following the malicious `setWifi` request and subsequent reboot, the device's debug console produces a kernel-level exception dump. The crash is fully reproducible across multiple reboots with identical register state, confirming deterministic memory corruption rather than a transient fault.


**Register state at crash:**
![](https://yzdhzjjwtsjwhabhuksf.supabase.co/storage/v1/object/public/assets/projects/Vuln_Research/AC8V2/REG.png)
![](https://yzdhzjjwtsjwhabhuksf.supabase.co/storage/v1/object/public/assets/projects/Vuln_Research/AC8V2/EPC.png)

**Key findings:**
- `PC` (Program Counter) = `0x41414141` — the processor attempted to fetch and execute an instruction directly from the attacker-supplied value. This is direct evidence of full instruction pointer hijack, not merely a crash.
- `R31` (`ra`, the MIPS return address register) = `0x41414141` — confirms the overflow overwrote the saved return address on the stack; the crash occurs at the point the overflowed function returns and jumps to the corrupted address.
- `s0`–`s7` registers (`R16`–`R23`) are also fully overwritten with `0x41414141`, showing the overflow spans well beyond the return address alone, into saved callee registers on the stack.
- `BADVR` / `BadVA` = `0x41414140` confirms the faulting fetch address directly corresponds to the attacker-controlled pattern (MIPS instruction-fetch alignment accounts for the trailing nibble offset).
- The stack dump is saturated with the attacker-supplied `0x41414141` pattern across dozens of contiguous words, confirming the overflow overwrote a large, contiguous region of the stack, consistent with no bounds checking whatsoever on the copy operation.

**Call stack trace** (from the `wps`/WPS-related thread context) shows the corrupted stack propagating through multiple stack frames before the final unrecoverable fetch:

![](https://yzdhzjjwtsjwhabhuksf.supabase.co/storage/v1/object/public/assets/projects/Vuln_Research/AC8V2/wps.png)

A secondary exception immediately follows as the exception handler itself attempts to unwind a stack that is still partially corrupted, producing a second TLB miss and ultimately a watchdog-triggered reboot loop — the device cycles through boot, re-reads the corrupted NVRAM value, crashes identically, and reboots again, indefinitely, without external intervention.
![](https://yzdhzjjwtsjwhabhuksf.supabase.co/storage/v1/object/public/assets/projects/Vuln_Research/AC8V2/2nd_exp.png)

### Impact

- **Denial of Service (persistent):** The device enters an unrecoverable boot loop. LAN, Wi-Fi, and the physical reset button are non-functional, as the crash occurs before user-facing services or the reset-to-defaults handler can initialize.
- **Recovery requires hardware-level intervention:** Normal recovery paths (web UI, reset button, TFTP recovery mode if gated behind the same boot path) are unavailable. Recovery was only possible via UART console access to the device's boot-stage flash monitor, directly reading and rewriting the corrupted flash regions.
- **Potential for Remote Code Execution:** Because PC and RA are both fully and precisely attacker-controlled (every byte of the 4-byte register is the attacker's chosen value), an attacker with knowledge of a valid, mapped, useful address (e.g., a ROP gadget or a location containing attacker-influenced data, such as the stack region itself if executable) could redirect execution to attacker-chosen code rather than an invalid address. This PoC used a non-exploitable placeholder address (`0x41414141`) to safely demonstrate control without weaponizing the primitive further.

- **Privileged execution context:** The corrupted `epc` (Exception Program Counter) is itself a CP0 (Coprocessor 0) register — CP0 holds all MIPS exception/interrupt state and is only accessible via privileged (`mtc0`/`mfc0`) instructions. Its overwrite with the attacker-supplied value, combined with the `Status` register's `KERNEL` mode bit (`10000403`) set at the time of the fault, confirms the hijacked instruction fetch occurred entirely within the processor's privileged execution context. The affected firmware is a single-address-space eCos RTOS with no user/kernel privilege separation between threads (the crashing `wps` thread runs at the same privilege level as networking, HTTP handling, and all other system services), so any code execution achieved via this primitive is inherently full-system, unrestricted-privilege execution — there is no lower-privileged boundary to escalate from.

### Reproduction Steps

1. Authenticate to the Tenda AC8 V2 web management interface or use the base 64 `ecos_pw` of intercepted request (Can be Unauthenticated if the owner did not set admin password).
2. Submit a `POST /goform/setWifi` request with the `wifiPwd` parameter set to an oversized value (315+ bytes of a fixed byte, e.g. `0x41`).
   - Refer to this python script:
   
   **WARNING:** This PoC modifies persistent router configuration and can render the device unusable. Recovery may require UART access and direct flash-level intervention. Test only on hardware you own or are explicitly authorized to assess.
```
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Replace BASE64PASSWORD with base64(admin_password)
# e.g. base64.b64encode(b'yourpassword').decode()
# leave ecos_pw for default routers (unauthenticated)
cookies = {
    'bLanguage': 'en',
    'ecos_pw': 'BASE64PASSWORD=',
    'language': 'cn',
}

headers = {
    'Host': '192.168.0.1',
    'Accept-Language': 'en-US,en;q=0.9',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept': '*/*',
    'Origin': 'http://192.168.0.1',
    'Referer': 'http://192.168.0.1/index.html',
    'Connection': 'keep-alive',
}

data = {
      # Complete the remaining required configuration parameters.
    'wifiPwd': 'A' * 315,  # 315 bytes — overflows stack buffer, smashes RA and PC
      .........
}

response = requests.post(
    'http://192.168.0.1/goform/setWifi',
    cookies=cookies,
    headers=headers,
    data=data,
    verify=False
)

print(response.status_code)
print(response.text)
# Expected: {"errCode":"0"} — device accepts oversized wifiPwd with no validation
# Device will become unresponsive on next boot/NVRAM read cycle
```
3. Observe the server responds `{"errCode":"0"}`, indicating the value was accepted with no validation.
4. The device becomes unresponsive shortly after (on NVRAM read/use of the corrupted value, typically on next boot or relevant service restart).
5. Connect to the device's UART header (TX/RX/GND) at 38400 baud rate and observe the kernel exception dump confirming the corruption, as detailed above.


## Supporting Weakness: Authentication Mechanism

By default, there is no session cookies if the admin password was not initialized. With that reason, it can be unauthenticated.
![](https://yzdhzjjwtsjwhabhuksf.supabase.co/storage/v1/object/public/assets/projects/Vuln_Research/AC8V2/unauth.png)

The captured request's session/authorization is carried entirely via a cookie containing the base64-encoded administrative password, rather than a server-issued, random session identifier:

```
Cookie: bLanguage=en; ecos_pw=YWRtaW4xMjM=; language=cn
```

`YWRtaW4xMjM=` decodes directly to the plaintext password `admin123`. This is encoding, not encryption or hashing, and the value does not change per session. This is relevant to the overall severity and exploitability of this finding:

- **No real session management** (CWE-384 / CWE-613): the "session" token is the credential itself, trivially reversible by any party who observes it (network capture, browser history/cache, referrer leakage, logging middleboxes, etc.), rather than an unpredictable, server-bound, expiring session identifier.
- **Insufficiently protected credentials** (CWE-522): because the password is recoverable by simply base64-decoding the cookie, interception of a single request yields the full admin credential, not just a replayable session.
- **Likely CSRF exposure** (CWE-352): since authorization is carried passively via a cookie with no additional anti-CSRF token binding the request to deliberate user action, a request to `goform/setWifi` (including this overflow payload) could plausibly be triggered via a malicious webpage or embedded request while an admin session cookie is present, without requiring the attacker to know the admin password directly.

This lowers the practical bar for an attacker to reach the `wifiPwd` overflow described above — compromising the authentication layer is not a strong barrier, and in a CSRF scenario may not be required at all.

## Recovery Procedure (tested)
- The AC8 V2 bootloader’s ERASESECTOR and FLW commands are non-functional — both silently accept commands but make no change to flash content (confirmed via CMP before/after comparison across multiple attempts including direct zero-byte overwrites, which must succeed on NOR flash physics). This rules out any purely bootloader-based recovery path.

- Recovery is instead achieved by racing the application-level CLI, which initializes in the main thread concurrently with the crashing WPS thread. The firmware’s own nvram set command correctly writes the value and recalculates the MD5 checksum for both Nvram and Snvram blocks — something raw FLW cannot do.


**Failed**
![](https://yzdhzjjwtsjwhabhuksf.supabase.co/storage/v1/object/public/assets/projects/Vuln_Research/AC8V2/cmp.png)

![](https://yzdhzjjwtsjwhabhuksf.supabase.co/storage/v1/object/public/assets/projects/Vuln_Research/AC8V2/erase.png)
- Nothing changed
![](https://yzdhzjjwtsjwhabhuksf.supabase.co/storage/v1/object/public/assets/projects/Vuln_Research/AC8V2/still.png)

![](https://yzdhzjjwtsjwhabhuksf.supabase.co/storage/v1/object/public/assets/projects/Vuln_Research/AC8V2/FLW.png)

- **Racing the CLI (worked)**
![](https://yzdhzjjwtsjwhabhuksf.supabase.co/storage/v1/object/public/assets/projects/Vuln_Research/AC8V2/recover.png)
- You can race the CLI and immediately set a password like `nvram set wl0_wpa_psk=password12`.

## Suggested Remediation

- Enforce strict server-side length validation on all `wifiPwd`/`wifiPwd_5G` and related configuration parameters in the `goform/setWifi` handler, rejecting any value exceeding the legitimate maximum (e.g., 63 characters per WPA/WPA2 PSK specification) before accepting or persisting the request.
- Replace unbounded copy operations (e.g., `strcpy`/`sprintf`) used when reading NVRAM-stored configuration values into stack buffers with bounded equivalents (e.g., `strncpy`/`snprintf`) sized to the destination buffer.
- Add NVRAM write-time validation to reject oversized values before they are committed to flash, independent of the HTTP-layer validation, as defense in depth.
- Replace the base64-encoded-password cookie with a proper server-issued, random, expiring session identifier, and implement anti-CSRF tokens on all state-changing endpoints including `goform/setWifi`.


