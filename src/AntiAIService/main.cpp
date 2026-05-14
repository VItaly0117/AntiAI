/*
 * AntiAIService — user-mode Windows service (MVP).
 * Periodically reads policy mode from the AntiAI kernel driver (best-effort).
 *
 * Install (elevated cmd):
 *   sc create AntiAIService binPath= "C:\full\path\AntiAIService.exe service" start= demand
 *   sc start AntiAIService
 * Uninstall:
 *   sc stop AntiAIService
 *   sc delete AntiAIService
 *
 * Foreground test (no SCM):
 *   AntiAIService.exe console
 *
 * WFP (optional, elevated service):
 *   Place AntiAIWfpBlacklist.txt next to the service executable (one IPv4/IPv6 per line).
 *   See src\\AntiAIWfp\\AntiAIWfpBlacklist.example.txt
 */

#include <windows.h>

#include <cstdio>
#include <cwchar>

#include "antiai_ioctl.h"
#include "wfp_blocklist.h"

#define SERVICE_NAME L"AntiAIService"

static SERVICE_STATUS g_ServiceStatus{};
static SERVICE_STATUS_HANDLE g_StatusHandle = nullptr;
static HANDLE g_StopEvent = nullptr;

static bool OpenAntiAI(_Out_ HANDLE *handle)
{
    *handle = CreateFileW(
        ANTIAI_USER_DEVICE_PATH,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (*handle == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    return true;
}

static void LogDriverModeSnapshot()
{
    HANDLE h = INVALID_HANDLE_VALUE;
    if (!OpenAntiAI(&h))
    {
        OutputDebugStringW(L"AntiAIService: driver not reachable (is AntiAIKernel installed and started?)\n");
        return;
    }

    ANTIAI_GET_MODE_OUT out{};
    DWORD bytes = 0;
    if (!DeviceIoControl(
            h,
            IOCTL_ANTIAI_GET_MODE,
            nullptr,
            0,
            &out,
            sizeof(out),
            &bytes,
            nullptr))
    {
        wchar_t buf[128];
        if (std::swprintf(
                buf,
                sizeof(buf) / sizeof(buf[0]),
                L"AntiAIService: IOCTL_ANTIAI_GET_MODE failed (%lu)\n",
                GetLastError())
            >= 0)
        {
            OutputDebugStringW(buf);
        }
        CloseHandle(h);
        return;
    }

    wchar_t buf[128];
    if (std::swprintf(
            buf,
            sizeof(buf) / sizeof(buf[0]),
            L"AntiAIService: current driver mode = %lu\n",
            static_cast<unsigned long>(out.Mode))
        >= 0)
    {
        OutputDebugStringW(buf);
    }
    CloseHandle(h);
}

static DWORD WINAPI ServiceCtrlHandlerEx(
    _In_ DWORD dwControl,
    _In_ DWORD dwEventType,
    _In_ LPVOID lpEventData,
    _In_ LPVOID lpContext)
{
    UNREFERENCED_PARAMETER(dwEventType);
    UNREFERENCED_PARAMETER(lpEventData);
    UNREFERENCED_PARAMETER(lpContext);

    switch (dwControl)
    {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING)
        {
            return NO_ERROR;
        }
        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        g_ServiceStatus.dwWin32ExitCode = 0;
        g_ServiceStatus.dwCheckPoint = 1;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        if (g_StopEvent)
        {
            SetEvent(g_StopEvent);
        }
        return NO_ERROR;
    case SERVICE_CONTROL_INTERROGATE:
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return NO_ERROR;
    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

static BOOL WINAPI ConsoleCtrlHandler(_In_ DWORD ctrlType)
{
    if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT || ctrlType == CTRL_CLOSE_EVENT)
    {
        if (g_StopEvent)
        {
            SetEvent(g_StopEvent);
        }
        return TRUE;
    }
    return FALSE;
}

static void RunWorkerLoop()
{
    for (;;)
    {
        const DWORD w = WaitForSingleObject(g_StopEvent, 30000);
        if (w == WAIT_OBJECT_0)
        {
            break;
        }
        LogDriverModeSnapshot();
    }
}

static void RunServiceBody()
{
    const HRESULT wfpHr = WfpBlacklistInit();
    if (FAILED(wfpHr))
    {
        wchar_t buf[160];
        if (std::swprintf(
                buf,
                sizeof(buf) / sizeof(buf[0]),
                L"AntiAIService: WfpBlacklistInit failed (0x%08lx)\n",
                static_cast<unsigned long>(wfpHr))
            >= 0)
        {
            OutputDebugStringW(buf);
        }
    }

    wchar_t blacklistPath[MAX_PATH] = {};
    if (GetModuleFileNameW(nullptr, blacklistPath, MAX_PATH) != 0)
    {
        PWSTR slash = wcsrchr(blacklistPath, L'\\');
        if (slash != nullptr)
        {
            *(slash + 1) = L'\0';
            if (wcscat_s(blacklistPath, MAX_PATH, L"AntiAIWfpBlacklist.txt") == 0)
            {
                const HRESULT hrReload = WfpReloadBlacklistFromFile(blacklistPath);
                if (hrReload == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND))
                {
                    OutputDebugStringW(L"AntiAIService: AntiAIWfpBlacklist.txt not found (optional).\n");
                }
                else if (FAILED(hrReload))
                {
                    wchar_t buf[200];
                    if (std::swprintf(
                            buf,
                            sizeof(buf) / sizeof(buf[0]),
                            L"AntiAIService: WfpReloadBlacklistFromFile failed (0x%08lx)\n",
                            static_cast<unsigned long>(hrReload))
                        >= 0)
                    {
                        OutputDebugStringW(buf);
                    }
                }
            }
        }
    }

    RunWorkerLoop();

    WfpBlacklistShutdown();
}

static VOID WINAPI ServiceMain(_In_ DWORD dwArgc, _In_ LPWSTR *lpszArgv)
{
    UNREFERENCED_PARAMETER(dwArgc);
    UNREFERENCED_PARAMETER(lpszArgv);

    g_StopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_StopEvent)
    {
        return;
    }

    g_StatusHandle = RegisterServiceCtrlHandlerExW(SERVICE_NAME, ServiceCtrlHandlerEx, nullptr);
    if (!g_StatusHandle)
    {
        CloseHandle(g_StopEvent);
        g_StopEvent = nullptr;
        return;
    }

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;
    g_ServiceStatus.dwWaitHint = 0;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    RunServiceBody();

    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    g_ServiceStatus.dwControlsAccepted = 0;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    CloseHandle(g_StopEvent);
    g_StopEvent = nullptr;
}

static void PrintUsage()
{
    std::fprintf(
        stderr,
        "AntiAIService (educational)\n"
        "  AntiAIService.exe service   (run under Service Control Manager)\n"
        "  AntiAIService.exe console   (foreground loop; prints to debugger via OutputDebugString)\n"
        "\n"
        "Example install (elevated):\n"
        "  sc create AntiAIService binPath= \"\\\"C:\\\\path\\\\AntiAIService.exe\\\" service\" start= demand\n");
}

int wmain(int argc, wchar_t *argv[])
{
    if (argc >= 2 && _wcsicmp(argv[1], L"console") == 0)
    {
        g_StopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!g_StopEvent)
        {
            std::fprintf(stderr, "CreateEvent failed: %lu\n", GetLastError());
            return 1;
        }
        SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);
        std::fprintf(stderr, "AntiAIService console mode (Ctrl+C to stop).\n");
        RunServiceBody();
        SetConsoleCtrlHandler(ConsoleCtrlHandler, FALSE);
        CloseHandle(g_StopEvent);
        g_StopEvent = nullptr;
        return 0;
    }

    if (argc >= 2 && _wcsicmp(argv[1], L"service") == 0)
    {
        static const SERVICE_TABLE_ENTRYW serviceTable[] = {
            {const_cast<LPWSTR>(SERVICE_NAME), static_cast<LPSERVICE_MAIN_FUNCTIONW>(ServiceMain)},
            {nullptr, nullptr},
        };

        if (!StartServiceCtrlDispatcherW(serviceTable))
        {
            std::fprintf(stderr, "StartServiceCtrlDispatcher failed: %lu\n", GetLastError());
            return 1;
        }
        return 0;
    }

    PrintUsage();
    return 1;
}
