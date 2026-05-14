/*
 * AntiAIControl.exe — educational C++ console for AntiAIKernel + WFP helpers.
 * Opens \\.\AntiAIKernel, uses DeviceIoControl; network blocks use documented WFP APIs.
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#include <cstdio>
#include <cwchar>

#include "antiai_ioctl.h"
#include "wfp_blocklist.h"

namespace {

void PrintUsage()
{
    std::fwprintf(
        stderr,
        L"AntiAIControl (educational)\n"
        L"  AntiAIControl.exe ping\n"
        L"  AntiAIControl.exe version\n"
        L"  AntiAIControl.exe status\n"
        L"  AntiAIControl.exe mode off | audit | block-network | block-process | block-all\n"
        L"  AntiAIControl.exe add-ip <IPv4-or-IPv6>          (WFP; run elevated)\n"
        L"  AntiAIControl.exe add-domain <hostname>        (DNS via GetAddrInfoW; WFP; elevated)\n"
        L"  AntiAIControl.exe clear-network-rules          (remove WFP block filters from this tool)\n"
        L"  AntiAIControl.exe test                         (driver ping/version/mode summary)\n");
}

void PrintWin32ErrorW(_In_z_ const wchar_t *context)
{
    const DWORD err = GetLastError();
    std::fwprintf(stderr, L"%ls failed. GetLastError=%lu (0x%08lx)\n", context, err, static_cast<unsigned long>(err));
}

void PrintWfpHresult(_In_z_ const wchar_t *context, HRESULT hr)
{
    std::fwprintf(
        stderr,
        L"%ls failed. HRESULT=0x%08lx (WFP/BFE often requires Administrator; GetLastError=%lu may be unrelated)\n",
        context,
        static_cast<unsigned long>(hr),
        static_cast<unsigned long>(GetLastError()));
}

bool EnsureWinsock()
{
    static bool s_started = false;
    if (s_started)
    {
        return true;
    }
    WSADATA wsa{};
    const int rc = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (rc != 0)
    {
        std::fwprintf(stderr, L"WSAStartup failed: %d\n", rc);
        return false;
    }
    s_started = true;
    return true;
}

bool OpenKernelDevice(_Out_ HANDLE *outHandle)
{
    *outHandle = CreateFileW(
        ANTIAI_USER_DEVICE_PATH,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (*outHandle == INVALID_HANDLE_VALUE)
    {
        PrintWin32ErrorW(L"CreateFileW(AntiAIKernel device)");
        return false;
    }
    return true;
}

bool DoPing()
{
    HANDLE h = INVALID_HANDLE_VALUE;
    if (!OpenKernelDevice(&h))
    {
        return false;
    }

    DWORD bytes = 0;
    const BOOL ok = DeviceIoControl(h, IOCTL_ANTIAI_PING, nullptr, 0, nullptr, 0, &bytes, nullptr);
    CloseHandle(h);

    if (!ok)
    {
        PrintWin32ErrorW(L"DeviceIoControl(IOCTL_ANTIAI_PING)");
        return false;
    }

    std::wprintf(L"OK: driver responded to ping.\n");
    return true;
}

bool DoVersion()
{
    HANDLE h = INVALID_HANDLE_VALUE;
    if (!OpenKernelDevice(&h))
    {
        return false;
    }

    ANTIAI_GET_VERSION_OUT out{};
    DWORD bytes = 0;
    const BOOL ok = DeviceIoControl(
        h,
        IOCTL_ANTIAI_GET_VERSION,
        nullptr,
        0,
        &out,
        sizeof(out),
        &bytes,
        nullptr);
    CloseHandle(h);

    if (!ok)
    {
        PrintWin32ErrorW(L"DeviceIoControl(IOCTL_ANTIAI_GET_VERSION)");
        return false;
    }

    std::wprintf(
        L"OK: AntiAIKernel driver version %u.%u (build %lu).\n",
        static_cast<unsigned>(out.Major),
        static_cast<unsigned>(out.Minor),
        static_cast<unsigned long>(out.Build));
    return true;
}

const wchar_t *PolicyModeLabel(_In_ ANTIAI_POLICY_MODE m)
{
    switch (m)
    {
    case ANTIAI_MODE_OFF:
        return L"off";
    case ANTIAI_MODE_AUDIT_ONLY:
        return L"audit";
    case ANTIAI_MODE_BLOCK_NETWORK:
        return L"block-network";
    case ANTIAI_MODE_BLOCK_PROCESS:
        return L"block-process";
    case ANTIAI_MODE_BLOCK_ALL:
        return L"block-all";
    default:
        return L"(unknown)";
    }
}

bool DoStatus()
{
    HANDLE h = INVALID_HANDLE_VALUE;
    if (!OpenKernelDevice(&h))
    {
        return false;
    }

    ANTIAI_GET_STATUS_OUT out{};
    DWORD bytes = 0;
    const BOOL ok = DeviceIoControl(
        h,
        IOCTL_ANTIAI_GET_STATUS,
        nullptr,
        0,
        &out,
        sizeof(out),
        &bytes,
        nullptr);
    CloseHandle(h);

    if (!ok)
    {
        PrintWin32ErrorW(L"DeviceIoControl(IOCTL_ANTIAI_GET_STATUS)");
        return false;
    }

    std::wprintf(
        L"OK: policy mode is %ls (enum=%lu), flags=0x%08lx.\n",
        PolicyModeLabel(out.PolicyMode),
        static_cast<unsigned long>(out.PolicyMode),
        static_cast<unsigned long>(out.Flags));
    return true;
}

bool DeviceSetMode(_In_ ANTIAI_POLICY_MODE mode)
{
    HANDLE h = INVALID_HANDLE_VALUE;
    if (!OpenKernelDevice(&h))
    {
        return false;
    }

    ANTIAI_SET_MODE_IN in{};
    in.Mode = mode;

    DWORD bytes = 0;
    const BOOL ok = DeviceIoControl(
        h,
        IOCTL_ANTIAI_SET_MODE,
        &in,
        sizeof(in),
        nullptr,
        0,
        &bytes,
        nullptr);
    CloseHandle(h);

    if (!ok)
    {
        PrintWin32ErrorW(L"DeviceIoControl(IOCTL_ANTIAI_SET_MODE)");
        return false;
    }

    std::wprintf(L"OK: kernel policy set to %ls.\n", PolicyModeLabel(mode));
    return true;
}

bool DoMode(_In_ const wchar_t *sub)
{
    if (sub == nullptr || sub[0] == L'\0')
    {
        PrintUsage();
        return false;
    }

    ANTIAI_POLICY_MODE mode = ANTIAI_MODE_OFF;
    if (_wcsicmp(sub, L"off") == 0)
    {
        mode = ANTIAI_MODE_OFF;
    }
    else if (_wcsicmp(sub, L"audit") == 0)
    {
        mode = ANTIAI_MODE_AUDIT_ONLY;
    }
    else if (_wcsicmp(sub, L"block-network") == 0)
    {
        mode = ANTIAI_MODE_BLOCK_NETWORK;
    }
    else if (_wcsicmp(sub, L"block-process") == 0)
    {
        mode = ANTIAI_MODE_BLOCK_PROCESS;
    }
    else if (_wcsicmp(sub, L"block-all") == 0)
    {
        mode = ANTIAI_MODE_BLOCK_ALL;
    }
    else
    {
        std::fwprintf(stderr, L"Unknown mode %ls\n", sub);
        PrintUsage();
        return false;
    }

    return DeviceSetMode(mode);
}

bool DoAddIp(_In_z_ const wchar_t *ipText)
{
    const HRESULT hrInit = WfpBlacklistInit();
    if (FAILED(hrInit))
    {
        PrintWfpHresult(L"WfpBlacklistInit", hrInit);
        return false;
    }

    const HRESULT hr = WfpAddBlockedIp(ipText);
    if (FAILED(hr))
    {
        PrintWfpHresult(L"WfpAddBlockedIp", hr);
        return false;
    }

    std::wprintf(L"OK: added WFP outbound block rule for IP %ls.\n", ipText);
    return true;
}

bool DoAddDomain(_In_z_ const wchar_t *host)
{
    if (!EnsureWinsock())
    {
        return false;
    }

    ADDRINFOW hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_ADDRCONFIG;

    ADDRINFOW *result = nullptr;
    const int gai = GetAddrInfoW(host, nullptr, &hints, &result);
    if (gai != 0)
    {
        std::fwprintf(stderr, L"GetAddrInfoW(%ls) failed: %d\n", host, gai);
        return false;
    }

    const HRESULT hrInit = WfpBlacklistInit();
    if (FAILED(hrInit))
    {
        FreeAddrInfoW(result);
        PrintWfpHresult(L"WfpBlacklistInit", hrInit);
        return false;
    }

    int added = 0;
    for (ADDRINFOW *p = result; p != nullptr; p = p->ai_next)
    {
        WCHAR ipString[INET6_ADDRSTRLEN] = {};

        if (p->ai_family == AF_INET)
        {
            const SOCKADDR_IN *sin = reinterpret_cast<const SOCKADDR_IN *>(p->ai_addr);
            if (InetNtopW(AF_INET, &sin->sin_addr, ipString, INET6_ADDRSTRLEN) == nullptr)
            {
                PrintWin32ErrorW(L"InetNtopW(AF_INET)");
                continue;
            }
        }
        else if (p->ai_family == AF_INET6)
        {
            const SOCKADDR_IN6 *sin6 = reinterpret_cast<const SOCKADDR_IN6 *>(p->ai_addr);
            if (InetNtopW(AF_INET6, &sin6->sin6_addr, ipString, INET6_ADDRSTRLEN) == nullptr)
            {
                PrintWin32ErrorW(L"InetNtopW(AF_INET6)");
                continue;
            }
        }
        else
        {
            continue;
        }

        const HRESULT hr = WfpAddBlockedIp(ipString);
        if (FAILED(hr))
        {
            std::fwprintf(stderr, L"Skipping %ls for domain %ls: ", ipString, host);
            PrintWfpHresult(L"WfpAddBlockedIp", hr);
            continue;
        }

        std::wprintf(L"OK: resolved %ls -> %ls; WFP block rule added.\n", host, ipString);
        ++added;
    }

    FreeAddrInfoW(result);

    if (added == 0)
    {
        std::fwprintf(stderr, L"No usable A/AAAA records added for %ls.\n", host);
        return false;
    }

    return true;
}

bool DoClearNetworkRules()
{
    WfpClearBlockedIps();
    std::wprintf(L"OK: cleared AntiAI WFP outbound block filters created by this tool.\n");
    return true;
}

bool DeviceGetMode(_Out_ ANTIAI_POLICY_MODE *mode)
{
    HANDLE h = INVALID_HANDLE_VALUE;
    if (!OpenKernelDevice(&h))
    {
        return false;
    }

    ANTIAI_GET_MODE_OUT out{};
    DWORD bytes = 0;
    const BOOL ok = DeviceIoControl(
        h,
        IOCTL_ANTIAI_GET_MODE,
        nullptr,
        0,
        &out,
        sizeof(out),
        &bytes,
        nullptr);
    CloseHandle(h);

    if (!ok)
    {
        PrintWin32ErrorW(L"DeviceIoControl(IOCTL_ANTIAI_GET_MODE)");
        return false;
    }

    *mode = out.Mode;
    return true;
}

bool DoTest()
{
    std::wprintf(L"--- AntiAI self-test ---\n");

    std::wprintf(L"[1/3] Ping driver ...\n");
    if (!DoPing())
    {
        std::fwprintf(stderr, L"Test stopped: driver not reachable.\n");
        return false;
    }

    std::wprintf(L"[2/3] Query driver version ...\n");
    if (!DoVersion())
    {
        std::fwprintf(stderr, L"Test stopped: version IOCTL failed.\n");
        return false;
    }

    std::wprintf(L"[3/3] Query policy mode ...\n");
    ANTIAI_POLICY_MODE m = ANTIAI_MODE_OFF;
    if (!DeviceGetMode(&m))
    {
        std::fwprintf(stderr, L"Test stopped: get-mode IOCTL failed.\n");
        return false;
    }

    std::wprintf(L"OK: current policy mode is %ls.\n", PolicyModeLabel(m));
    std::wprintf(L"--- Test finished successfully ---\n");
    return true;
}

} // namespace

int wmain(int argc, wchar_t *argv[])
{
    if (argc < 2)
    {
        PrintUsage();
        return 1;
    }

    if (_wcsicmp(argv[1], L"ping") == 0)
    {
        return DoPing() ? 0 : 1;
    }
    if (_wcsicmp(argv[1], L"version") == 0)
    {
        return DoVersion() ? 0 : 1;
    }
    if (_wcsicmp(argv[1], L"status") == 0)
    {
        return DoStatus() ? 0 : 1;
    }
    if (_wcsicmp(argv[1], L"test") == 0)
    {
        return DoTest() ? 0 : 1;
    }
    if (_wcsicmp(argv[1], L"clear-network-rules") == 0)
    {
        return DoClearNetworkRules() ? 0 : 1;
    }

    if (_wcsicmp(argv[1], L"mode") == 0)
    {
        if (argc < 3)
        {
            PrintUsage();
            return 1;
        }
        return DoMode(argv[2]) ? 0 : 1;
    }

    if (_wcsicmp(argv[1], L"add-ip") == 0)
    {
        if (argc < 3)
        {
            PrintUsage();
            return 1;
        }
        return DoAddIp(argv[2]) ? 0 : 1;
    }

    if (_wcsicmp(argv[1], L"add-domain") == 0)
    {
        if (argc < 3)
        {
            PrintUsage();
            return 1;
        }
        return DoAddDomain(argv[2]) ? 0 : 1;
    }

    PrintUsage();
    return 1;
}
