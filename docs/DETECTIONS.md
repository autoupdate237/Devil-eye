# Devil's Eye — Detection Catalogue

Every detection in Devil's Eye is documented in the mandatory format:

> **What was detected → Where it was detected → Which evidence supports it →
> Confidence → Risk contribution**

Rules fire into *indicators*; indicators never equal verdicts. Verdicts are
produced by the scoring engine from the aggregate, allowlist-dampened,
coverage-scaled picture.


## Category: `ancestry`

### DE-ANC-001 — Protected process launched by a scripting/shell host

| Aspect | Detail |
|---|---|
| **What** | The protected game was started by cmd/powershell/wscript/mshta instead of its normal launcher. |
| **Where** | Process tree (parent→child relation). |
| **Evidence** | Process evidence for both parent and child. |
| **Base confidence** | 0.65 |
| **Severity** | 6.0 / 10 |
| **Risk contribution** | Medium-high for games; cheat loaders frequently boot games through a shell. |

## Category: `command_line`

### DE-CMD-001 — Suspicious command-line pattern

| Aspect | Detail |
|---|---|
| **What** | Command line matches known injection/obfuscation/living-off-the-land patterns. |
| **Where** | Process command line (process inventory / Sysmon EID1 / Security 4688). |
| **Evidence** | Process evidence carrying the raw command line. |
| **Base confidence** | pattern-dependent |
| **Severity** | 5.0 / 10 |
| **Risk contribution** | Varies by pattern; encoded PowerShell alone is low, explicit --inject is high. |

## Category: `driver`

### DE-DRV-001 — Driver with invalid or missing signature

| Aspect | Detail |
|---|---|
| **What** | A kernel driver is unsigned or fails integrity checks. |
| **Where** | Driver inventory + CodeIntegrity operational events. |
| **Evidence** | Driver evidence + CodeIntegrity 3033/3034 events when present. |
| **Base confidence** | 0.9 |
| **Severity** | 10.0 / 10 |
| **Risk contribution** | Critical: ring-0 code can read/write any game memory. |

## Category: `file_integrity`

### DE-FILE-001 — Prefetch proves execution of a staged binary

| Aspect | Detail |
|---|---|
| **What** | Prefetch contains an entry for a binary that is also staged in a temp dir — executed, not just dropped. |
| **Where** | C:\Windows\Prefetch. |
| **Evidence** | Prefetch artifact evidence + matching process/persistence path. |
| **Base confidence** | 0.8 |
| **Severity** | 4.0 / 10 |
| **Risk contribution** | Low alone, but upgrades drop-only findings to 'executed'. |

## Category: `memory_integrity`

### DE-MEM-001 — Executable private memory in the protected process

| Aspect | Detail |
|---|---|
| **What** | MEM_PRIVATE region with execute protection — classic shellcode/injected-code shape. |
| **Where** | Virtual memory region metadata of the protected process. |
| **Evidence** | Memory region evidence (base/size/state/protect). |
| **Base confidence** | 0.75 |
| **Severity** | 8.0 / 10 |
| **Risk contribution** | High for a protected game (JIT engines normally use image-backed or RW→RX transitions). |

### DE-MEM-002 — Thread start address outside any module

| Aspect | Detail |
|---|---|
| **What** | A thread begins executing at an address not backed by a mapped image — injected thread. |
| **Where** | Thread metadata of the protected process. |
| **Evidence** | Thread evidence (tid/start_address/backing module). |
| **Base confidence** | 0.85 |
| **Severity** | 9.0 / 10 |
| **Risk contribution** | Very high: legitimate threads start inside ntdll/CLR/loader stubs. |

## Category: `module_integrity`

### DE-MOD-001 — Unsigned module loaded into the protected process

| Aspect | Detail |
|---|---|
| **What** | A DLL without a valid signature is mapped into the protected game. |
| **Where** | Module inventory of the protected process. |
| **Evidence** | Module evidence (path/base/size) + signature evidence. |
| **Base confidence** | 0.85 |
| **Severity** | 8.0 / 10 |
| **Risk contribution** | High: injected cheat DLLs are typically unsigned or stolen-signed. |

### DE-MOD-002 — System module masquerading (wrong path)

| Aspect | Detail |
|---|---|
| **What** | A module carries the name of a core Windows DLL but is loaded from outside System32/SysWOW64. |
| **Where** | Module inventory; path vs. canonical system directories. |
| **Evidence** | Module evidence with path + name; catalog of canonical locations. |
| **Base confidence** | 0.9 |
| **Severity** | 9.0 / 10 |
| **Risk contribution** | Very high: ntdll/kernel32 can only legitimately come from system directories. |

### DE-MOD-003 — Module loaded from temp/public directory

| Aspect | Detail |
|---|---|
| **What** | A DLL is mapped from a staging directory into any process. |
| **Where** | Module inventory. |
| **Evidence** | Module evidence (path). |
| **Base confidence** | 0.7 |
| **Severity** | 5.0 / 10 |
| **Risk contribution** | Medium: updaters do this occasionally; corroborate before escalation. |

## Category: `network`

### DE-NET-001 — Unsigned/staged process with established outbound connection

| Aspect | Detail |
|---|---|
| **What** | A process whose binary is unsigned or staged in a temp dir holds an ESTABLISHED connection. |
| **Where** | TCP connection table joined with process + signature data. |
| **Evidence** | Network evidence + process + signature evidence. |
| **Base confidence** | 0.7 |
| **Severity** | 6.0 / 10 |
| **Risk contribution** | Medium-high: C2 for loaders; benign portable tools can false-positive → dampening applied. |

## Category: `persistence`

### DE-PERS-001 — Run key pointing at writable/shared location

| Aspect | Detail |
|---|---|
| **What** | An autorun (Run/RunOnce) value starts a binary from Temp/Public/AppData. |
| **Where** | HKLM/HKCU Run keys. |
| **Evidence** | Registry evidence (hive/key/value/data). |
| **Base confidence** | 0.8 |
| **Severity** | 7.0 / 10 |
| **Risk contribution** | High: boots with the user session on every logon. |

### DE-PERS-002 — IFEO debugger hijack

| Aspect | Detail |
|---|---|
| **What** | Image File Execution Options sets a Debugger for an image — execution redirection. |
| **Where** | HKLM\...\Image File Execution Options\<image>. |
| **Evidence** | Registry evidence for the IFEO subkey. |
| **Base confidence** | 0.9 |
| **Severity** | 9.0 / 10 |
| **Risk contribution** | Very high when the debugger path is not a trusted debugger (especially on the protected game). |

### DE-PERS-003 — AppInit_DLLs configured

| Aspect | Detail |
|---|---|
| **What** | AppInit_DLLs loads a DLL into every GUI process at startup. |
| **Where** | HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows. |
| **Evidence** | Registry evidence. |
| **Base confidence** | 0.75 |
| **Severity** | 7.0 / 10 |
| **Risk contribution** | High: global injection primitive (mostly disabled on modern Windows, still a red flag). |

## Category: `process_integrity`

### DE-PROC-001 — Unsigned executable outside trusted directories

| Aspect | Detail |
|---|---|
| **What** | A running executable has no valid Authenticode signature and lives outside trusted OS directories. |
| **Where** | Process inventory (path of the image). |
| **Evidence** | Process evidence + Authenticode status evidence for the same path. |
| **Base confidence** | 0.6 |
| **Severity** | 4.0 / 10 |
| **Risk contribution** | Weak on its own; gains weight only when corroborated (modules, network, telemetry). |

### DE-PROC-002 — Executable running from world-writable/shared location

| Aspect | Detail |
|---|---|
| **What** | Code executes from Users\Public, Temp or INetCache — classic dropper staging areas. |
| **Where** | Process inventory + file path. |
| **Evidence** | Process evidence; path string; signature status when present. |
| **Base confidence** | 0.7 |
| **Severity** | 6.0 / 10 |
| **Risk contribution** | Medium: legitimate installers sometimes stage here, so confidence stays moderate. |

## Category: `scheduled_task`

### DE-TASK-001 — Scheduled task executing from temp

| Aspect | Detail |
|---|---|
| **What** | A scheduled task's action runs a binary staged in Temp/AppData temp. |
| **Where** | Task Scheduler registrations (XML / TaskCache). |
| **Evidence** | Task evidence (actions string). |
| **Base confidence** | 0.75 |
| **Severity** | 7.0 / 10 |
| **Risk contribution** | High: common fileless persistence. |

## Category: `service`

### DE-SVC-001 — Service pointing at unsigned binary in writable path

| Aspect | Detail |
|---|---|
| **What** | An installed service runs an unsigned binary from Temp/Public/AppData. |
| **Where** | Service configuration (ImagePath). |
| **Evidence** | Service evidence + signature evidence for the image path. |
| **Base confidence** | 0.8 |
| **Severity** | 8.0 / 10 |
| **Risk contribution** | High: persistence with SYSTEM start. |

## Category: `signature`

### DE-SIG-001 — Broken/tampered Authenticode signature

| Aspect | Detail |
|---|---|
| **What** | Signature validation failed (HashMismatch/NotSigned-on-expected/revoked) for a running image. |
| **Where** | Authenticode verification result for the file path. |
| **Evidence** | Signature evidence (status, publisher, chain validity). |
| **Base confidence** | 0.9 |
| **Severity** | 8.0 / 10 |
| **Risk contribution** | High: a *broken* signature (vs. absent) usually means a modified binary. |

## Category: `telemetry`

### DE-TEL-001 — CreateRemoteThread into the protected process

| Aspect | Detail |
|---|---|
| **What** | Sysmon EID 8: another process created a thread inside the protected game. |
| **Where** | Microsoft-Windows-Sysmon/Operational. |
| **Evidence** | Event evidence (EID 8) with source/target images. |
| **Base confidence** | 0.85 |
| **Severity** | 9.0 / 10 |
| **Risk contribution** | Very high: the canonical DLL/shellcode injection signal. |

### DE-TEL-002 — High-rights process access to the protected process

| Aspect | Detail |
|---|---|
| **What** | Sysmon EID 10: a process opened the game with VM_WRITE/ALL_ACCESS rights. |
| **Where** | Microsoft-Windows-Sysmon/Operational. |
| **Evidence** | Event evidence (EID 10) GrantedAccess. |
| **Base confidence** | 0.7 |
| **Severity** | 7.0 / 10 |
| **Risk contribution** | High: write access to game memory is the cheat primitive. |

### DE-TEL-003 — Defender detection references an observed binary

| Aspect | Detail |
|---|---|
| **What** | Microsoft Defender flagged a path that also appears in our process/persistence evidence. |
| **Where** | Defender Operational / Get-MpThreatDetection. |
| **Evidence** | Defender detection evidence + matching process/persistence evidence. |
| **Base confidence** | 0.8 |
| **Severity** | 8.0 / 10 |
| **Risk contribution** | High: independent security product corroborates our findings. |

## Category: `wmi`

### DE-WMI-001 — WMI permanent subscription with script consumer

| Aspect | Detail |
|---|---|
| **What** | A __EventFilter is permanently bound to an ActiveScript/CommandLine consumer. |
| **Where** | WMI repository (root\subscription). |
| **Evidence** | Filter/consumer/binding evidence. |
| **Base confidence** | 0.7 |
| **Severity** | 7.0 / 10 |
| **Risk contribution** | High: fileless persistence used by real intrusions. |
