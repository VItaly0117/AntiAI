# AntiAI Windows Driver MVP

AntiAI is an educational Windows driver MVP for a school/hackathon demo. It is intentionally small and explicit: no stealth, no injection, no anti-uninstall behavior, no bypass logic, and no kernel network callout.

## Projects

- `AntiAIKernel`: KMDF driver.
- `AntiAIControl`: user-mode CLI for driver IOCTLs and WFP helper commands.
- `AntiAIService`: optional Windows service / console monitor.
- `AntiAIWfp`: user-mode Windows Filtering Platform helper.
- `Shared`: common headers used by kernel and user mode.

## Device names

The current code uses these names:

- Kernel device: `\Device\AntiAIKernel`
- Symbolic link: `\DosDevices\AntiAIKernel`
- User-mode path: `\\.\AntiAIKernel`

`AntiAIControl` and `AntiAIService` both open `ANTIAI_USER_DEVICE_PATH`, defined in `src/Shared/include/antiai_ioctl.h` as `L"\\\\.\\AntiAIKernel"`.

## IOCTL contract

All IOCTLs use `METHOD_BUFFERED` and `FILE_ANY_ACCESS`.

```c
#define ANTIAI_DEVICE_TYPE 0x8100u

#define IOCTL_ANTIAI_PING        CTL_CODE(ANTIAI_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ANTIAI_GET_VERSION CTL_CODE(ANTIAI_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ANTIAI_GET_STATUS  CTL_CODE(ANTIAI_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ANTIAI_SET_MODE    CTL_CODE(ANTIAI_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ANTIAI_GET_MODE    CTL_CODE(ANTIAI_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

Payload structs are defined in `src/Shared/include/antiai_ioctl.h`:

- `ANTIAI_SET_MODE_IN`: input for `SET_MODE`.
- `ANTIAI_GET_MODE_OUT`: output for `GET_MODE`.
- `ANTIAI_GET_VERSION_OUT`: output for `GET_VERSION`.
- `ANTIAI_GET_STATUS_OUT`: output for `GET_STATUS`.

## Policy modes

Policy modes are defined in `src/Shared/include/antiai_policy.h`:

- `ANTIAI_MODE_OFF = 0`
- `ANTIAI_MODE_AUDIT_ONLY = 1`
- `ANTIAI_MODE_BLOCK_NETWORK = 2`
- `ANTIAI_MODE_BLOCK_PROCESS = 3`
- `ANTIAI_MODE_BLOCK_ALL = 4`

CLI mapping:

```cmd
AntiAIControl.exe mode off
AntiAIControl.exe mode audit
AntiAIControl.exe mode block-network
AntiAIControl.exe mode block-process
AntiAIControl.exe mode block-all
```

## Process guard

`src/AntiAIKernel/process_guard.c` registers `PsSetCreateProcessNotifyRoutineEx` at driver load and unregisters it at unload.

Current behavior:

- `OFF` and `BLOCK_NETWORK`: process guard returns immediately.
- `AUDIT_ONLY`: exact filename matches are logged with `KdPrintEx`; no process is denied.
- `BLOCK_PROCESS` and `BLOCK_ALL`: exact filename matches are denied by setting `CreateInfo->CreationStatus = STATUS_ACCESS_DENIED`.
- `python.exe` is never blocked or audit-logged by this module.
- Blocking is limited to exact image filenames `fake_ai_tool.exe` and `ollama.exe`.
- Paths containing `\Windows\System32\` or `\Windows\SysWOW64\` are ignored.

The process guard does not terminate existing processes. It only denies matching process creation requests in the notify callback.

## WFP helper

`AntiAIWfp` is a user-mode WFP MVP. It opens the filtering engine with `FwpmEngineOpen0`, creates an AntiAI provider and sublayer, and installs outbound `FWP_ACTION_BLOCK` filters on:

- `FWPM_LAYER_ALE_AUTH_CONNECT_V4`
- `FWPM_LAYER_ALE_AUTH_CONNECT_V6`

It does not register a kernel callout, modify packets, proxy traffic, inspect TLS, or communicate with the kernel driver. `AntiAIControl` exposes:

```cmd
AntiAIControl.exe add-ip <IPv4-or-IPv6>
AntiAIControl.exe add-domain <hostname>
AntiAIControl.exe clear-network-rules
```

`add-domain` resolves the hostname with `GetAddrInfoW` and adds one filter per A/AAAA result. CDN and dynamic DNS behavior means hostname blocking is best-effort for demos.

IPv4 literals are parsed with `InetPtonW` and converted to WFP `FWP_UINT32` host order before the filter is added. IPv6 literals are stored as `FWP_BYTE_ARRAY16_TYPE`.

## Build

Open a VS 2022 Developer Command Prompt with WDK installed, then run:

```cmd
cd /d D:\team_work_code\AntiAI
msbuild AntiAI.sln /m /p:Configuration=Release /p:Platform=x64
```

Useful single-project builds:

```cmd
msbuild src\AntiAIKernel\AntiAIKernel.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild src\AntiAIWfp\AntiAIWfp.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild src\AntiAIControl\AntiAIControl.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild src\AntiAIService\AntiAIService.vcxproj /p:Configuration=Release /p:Platform=x64
```

Expected Release outputs:

- `src\AntiAIKernel\x64\Release\AntiAIKernel.sys`
- `src\AntiAIControl\x64\Release\AntiAIControl.exe`
- `src\AntiAIService\x64\Release\AntiAIService.exe`

## Demo test commands

Run these in an elevated command prompt inside a Windows 10 x64 VM with test signing enabled.

```cmd
bcdedit /set testsigning on
shutdown /r /t 0
```

After reboot, install/start the driver from the built `.sys` path:

```cmd
sc create AntiAIKernel type= kernel binPath= "D:\team_work_code\AntiAI\src\AntiAIKernel\x64\Release\AntiAIKernel.sys" start= demand
sc start AntiAIKernel
sc query AntiAIKernel
```

Driver IOCTL smoke tests:

```cmd
D:\team_work_code\AntiAI\src\AntiAIControl\x64\Release\AntiAIControl.exe ping
D:\team_work_code\AntiAI\src\AntiAIControl\x64\Release\AntiAIControl.exe version
D:\team_work_code\AntiAI\src\AntiAIControl\x64\Release\AntiAIControl.exe status
D:\team_work_code\AntiAI\src\AntiAIControl\x64\Release\AntiAIControl.exe test
```

Process-guard demo:

```cmd
D:\team_work_code\AntiAI\src\AntiAIControl\x64\Release\AntiAIControl.exe mode audit
fake_ai_tool.exe
ollama.exe
python.exe

D:\team_work_code\AntiAI\src\AntiAIControl\x64\Release\AntiAIControl.exe mode block-process
fake_ai_tool.exe
ollama.exe
python.exe

D:\team_work_code\AntiAI\src\AntiAIControl\x64\Release\AntiAIControl.exe mode off
```

WFP helper demo, elevated:

```cmd
D:\team_work_code\AntiAI\src\AntiAIControl\x64\Release\AntiAIControl.exe add-ip 1.2.3.4
D:\team_work_code\AntiAI\src\AntiAIControl\x64\Release\AntiAIControl.exe clear-network-rules
```

Optional service / console monitor:

```cmd
D:\team_work_code\AntiAI\src\AntiAIService\x64\Release\AntiAIService.exe console
```

Cleanup:

```cmd
sc stop AntiAIKernel
sc delete AntiAIKernel
```
