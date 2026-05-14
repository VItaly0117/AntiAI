/*
 * Educational process creation guard using PsSetCreateProcessNotifyRoutineEx.
 * VM / lab use only. No stealth, no injection, no user-mode buffer dereference.
 */

#define POOL_NX_OPTIN 1

#include <ntddk.h>

#include "process_guard.h"

static volatile LONG g_PolicyMode = (LONG)ANTIAI_MODE_OFF;
static BOOLEAN g_CallbackRegistered = FALSE;

static const WCHAR g_PatSystem32[] = L"\\Windows\\System32\\";
static const WCHAR g_PatSysWow64[] = L"\\Windows\\SysWOW64\\";

static USHORT AntiAIConstUnicodeCch(_In_reads_(cch) const WCHAR *s, USHORT cchMax)
{
    USHORT i = 0;
    while (i < cchMax && s[i] != L'\0')
    {
        ++i;
    }
    return i;
}

static WCHAR AntiAILowerAsciiWchar(_In_ WCHAR ch)
{
    if (ch >= L'A' && ch <= L'Z')
    {
        return (WCHAR)(ch + (L'a' - L'A'));
    }
    return ch;
}

/*
 * Bounded, ASCII-only case-insensitive substring search for well-known path tokens.
 * Not a general Unicode case-folding implementation.
 */
static BOOLEAN AntiAIUnicodeContainsAsciiTokenCi(
    _In_reads_bytes_(haystackBytes) PCWSTR haystack,
    _In_ USHORT haystackCch,
    _In_reads_(tokenCch) const WCHAR *token,
    _In_ USHORT tokenCch)
{
    USHORT i;
    USHORT j;

    if (tokenCch == 0 || haystackCch < tokenCch)
    {
        return FALSE;
    }

    for (i = 0; i + tokenCch <= haystackCch; ++i)
    {
        for (j = 0; j < tokenCch; ++j)
        {
            if (AntiAILowerAsciiWchar(haystack[i + j]) != AntiAILowerAsciiWchar(token[j]))
            {
                break;
            }
        }
        if (j == tokenCch)
        {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN AntiAIImageUnderSystemDirs(_In_ PCUNICODE_STRING image)
{
    USHORT cch;

    if (image == NULL || image->Buffer == NULL || image->Length == 0)
    {
        return FALSE;
    }

    cch = image->Length / sizeof(WCHAR);

    if (AntiAIUnicodeContainsAsciiTokenCi(
            image->Buffer,
            cch,
            g_PatSystem32,
            AntiAIConstUnicodeCch(g_PatSystem32, 64)))
    {
        return TRUE;
    }

    if (AntiAIUnicodeContainsAsciiTokenCi(
            image->Buffer,
            cch,
            g_PatSysWow64,
            AntiAIConstUnicodeCch(g_PatSysWow64, 64)))
    {
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN AntiAIRtlSuffixUnicodeStringCi(
    _In_ PCUNICODE_STRING string,
    _In_ PCUNICODE_STRING suffix)
{
    return RtlSuffixUnicodeString((PUNICODE_STRING)string, (PUNICODE_STRING)suffix, TRUE) == STATUS_SUCCESS;
}

static BOOLEAN AntiAIImageMatchesDemoDenylist(_In_ PCUNICODE_STRING image)
{
    UNICODE_STRING uPython;
    UNICODE_STRING uFake;
    UNICODE_STRING uOllama;

    RtlInitUnicodeString(&uPython, L"python.exe");
    RtlInitUnicodeString(&uFake, L"fake_ai_tool.exe");
    RtlInitUnicodeString(&uOllama, L"ollama.exe");

    if (AntiAIImageUnderSystemDirs(image))
    {
        return FALSE;
    }

    if (AntiAIRtlSuffixUnicodeStringCi(image, &uPython))
    {
        return FALSE;
    }

    if (AntiAIRtlSuffixUnicodeStringCi(image, &uFake))
    {
        return TRUE;
    }

    if (AntiAIRtlSuffixUnicodeStringCi(image, &uOllama))
    {
        return TRUE;
    }

    return FALSE;
}

static VOID NTAPI AntiAIProcessNotifyCallbackEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    ANTIAI_POLICY_MODE mode;

    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ProcessId);

    if (CreateInfo == NULL)
    {
        return;
    }

    /*
     * Keep this path tiny: a few comparisons and at most one KdPrintEx / status write.
     * Do not acquire locks, allocate pool, touch paged code unsafely, or parse user buffers.
     */

    mode = (ANTIAI_POLICY_MODE)InterlockedCompareExchange(&g_PolicyMode, 0, 0);

    if (mode == ANTIAI_MODE_OFF || mode == ANTIAI_MODE_BLOCK_NETWORK)
    {
        return;
    }

    if (CreateInfo->ImageFileName == NULL || CreateInfo->ImageFileName->Buffer == NULL)
    {
        return;
    }

    if ((CreateInfo->ImageFileName->Length % sizeof(WCHAR)) != 0)
    {
        return;
    }

    if (!AntiAIImageMatchesDemoDenylist(CreateInfo->ImageFileName))
    {
        return;
    }

    if (mode == ANTIAI_MODE_AUDIT_ONLY)
    {
        KdPrintEx((
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_INFO_LEVEL,
            "AntiAIKernel process_guard: AUDIT_ONLY match (no deny) for image %wZ\n",
            CreateInfo->ImageFileName));
        return;
    }

    if (mode == ANTIAI_MODE_BLOCK_PROCESS || mode == ANTIAI_MODE_BLOCK_ALL)
    {
        KdPrintEx((
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_INFO_LEVEL,
            "AntiAIKernel process_guard: denying create for %wZ\n",
            CreateInfo->ImageFileName));
        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
    }
}

NTSTATUS ProcessGuardInitialize(void)
{
    NTSTATUS status;

    if (g_CallbackRegistered)
    {
        return STATUS_SUCCESS;
    }

    status = PsSetCreateProcessNotifyRoutineEx(AntiAIProcessNotifyCallbackEx, FALSE);
    if (!NT_SUCCESS(status))
    {
        KdPrintEx((
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "AntiAIKernel process_guard: PsSetCreateProcessNotifyRoutineEx failed %08X\n",
            status));
        return status;
    }

    g_CallbackRegistered = TRUE;
    InterlockedExchange(&g_PolicyMode, (LONG)ANTIAI_MODE_OFF);
    return STATUS_SUCCESS;
}

void ProcessGuardShutdown(void)
{
    if (!g_CallbackRegistered)
    {
        return;
    }

    PsSetCreateProcessNotifyRoutineEx(AntiAIProcessNotifyCallbackEx, TRUE);
    g_CallbackRegistered = FALSE;
    InterlockedExchange(&g_PolicyMode, (LONG)ANTIAI_MODE_OFF);
}

void ProcessGuardSetPolicyMode(_In_ ANTIAI_POLICY_MODE mode)
{
    InterlockedExchange(&g_PolicyMode, (LONG)mode);
}
