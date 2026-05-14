/*
 * User-mode WFP MVP: outbound connect deny by remote IPv4/IPv6 literal.
 * Requires elevation. No callouts, no packet modification.
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <initguid.h>
#include <fwpmu.h>
#include <rpc.h>

#include <algorithm>
#include <cwctype>
#include <cstring>
#include <fstream>
#include <mutex>
#include <string>
#include <vector>

#include "wfp_blocklist.h"

DEFINE_GUID(
    ANTI_AI_WFP_PROVIDER_KEY,
    0x6a7f2e3d,
    0x1a01,
    0x4b2c,
    0x9e,
    0x8f,
    0x0d,
    0x1c,
    0x2b,
    0x3a,
    0x40,
    0x50);

DEFINE_GUID(
    ANTI_AI_WFP_SUBLAYER_KEY,
    0x6a7f2e3d,
    0x1a01,
    0x4b2c,
    0x9e,
    0x8f,
    0x0d,
    0x1c,
    0x2b,
    0x3a,
    0x40,
    0x51);

namespace {

std::recursive_mutex g_lock;
HANDLE g_engine = nullptr;
bool g_wsaStarted = false;
std::vector<GUID> g_filterKeys;

static void TrimInPlace(std::wstring &s)
{
    while (!s.empty() && std::iswspace(static_cast<wint_t>(s.front())))
    {
        s.erase(s.begin());
    }
    while (!s.empty() && std::iswspace(static_cast<wint_t>(s.back())))
    {
        s.pop_back();
    }
}

static HRESULT EnsureProviderAndSublayer(HANDLE engine)
{
    FWPM_PROVIDER0 provider{};
    provider.providerKey = ANTI_AI_WFP_PROVIDER_KEY;
    provider.displayData.name = const_cast<PWSTR>(L"AntiAI (Educational)");
    provider.displayData.description =
        const_cast<PWSTR>(L"User-mode WFP provider for lab outbound IP deny MVP");

    DWORD err = FwpmProviderAdd0(engine, &provider, nullptr);
    if (err != ERROR_SUCCESS && err != static_cast<DWORD>(0x80320009u)) /* FWP_E_ALREADY_EXISTS */
    {
        return HRESULT_FROM_WIN32(err);
    }

    FWPM_SUBLAYER0 sublayer{};
    sublayer.subLayerKey = ANTI_AI_WFP_SUBLAYER_KEY;
    sublayer.displayData.name = const_cast<PWSTR>(L"AntiAI educational sublayer");
    sublayer.displayData.description =
        const_cast<PWSTR>(L"Hosts block filters for ALE_AUTH_CONNECT_* layers");
    sublayer.providerKey = ANTI_AI_WFP_PROVIDER_KEY;
    sublayer.weight = 0x100;

    err = FwpmSubLayerAdd0(engine, &sublayer, nullptr);
    if (err != ERROR_SUCCESS && err != static_cast<DWORD>(0x80320009u)) /* FWP_E_ALREADY_EXISTS */
    {
        return HRESULT_FROM_WIN32(err);
    }

    return S_OK;
}

static HRESULT OpenEngineAndInstallPrimitivesLocked()
{
    if (g_engine != nullptr)
    {
        return S_OK;
    }

    if (!g_wsaStarted)
    {
        WSADATA wsa{};
        const int wsaErr = WSAStartup(MAKEWORD(2, 2), &wsa);
        if (wsaErr != 0)
        {
            return HRESULT_FROM_WIN32(static_cast<DWORD>(wsaErr));
        }
        g_wsaStarted = true;
    }

    DWORD err = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &g_engine);
    if (err != ERROR_SUCCESS)
    {
        return HRESULT_FROM_WIN32(err);
    }

    err = FwpmTransactionBegin0(g_engine, 0);
    if (err != ERROR_SUCCESS)
    {
        FwpmEngineClose0(g_engine);
        g_engine = nullptr;
        return HRESULT_FROM_WIN32(err);
    }

    const HRESULT hrEnsure = EnsureProviderAndSublayer(g_engine);
    if (FAILED(hrEnsure))
    {
        FwpmTransactionAbort0(g_engine);
        FwpmEngineClose0(g_engine);
        g_engine = nullptr;
        return hrEnsure;
    }

    err = FwpmTransactionCommit0(g_engine);
    if (err != ERROR_SUCCESS)
    {
        FwpmTransactionAbort0(g_engine);
        FwpmEngineClose0(g_engine);
        g_engine = nullptr;
        return HRESULT_FROM_WIN32(err);
    }

    return S_OK;
}

static HRESULT AddBlockedIpLocked(PCWSTR ipText)
{
    const HRESULT hrOpen = OpenEngineAndInstallPrimitivesLocked();
    if (FAILED(hrOpen))
    {
        return hrOpen;
    }

    IN_ADDR v4{};
    IN6_ADDR v6{};
    const int v4Ok = InetPtonW(AF_INET, ipText, &v4);
    const int v6Ok = (v4Ok != 1) ? InetPtonW(AF_INET6, ipText, &v6) : 0;
    if (v4Ok != 1 && v6Ok != 1)
    {
        return E_INVALIDARG;
    }

    const bool isV4 = (v4Ok == 1);

    GUID filterKey{};
    const RPC_STATUS rs = UuidCreate(&filterKey);
    if (rs != RPC_S_OK && rs != RPC_S_UUID_LOCAL_ONLY)
    {
        return E_FAIL;
    }

    FWPM_FILTER_CONDITION0 cond{};
    FWP_BYTE_ARRAY16 v6Bytes{};

    if (isV4)
    {
        cond.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        cond.matchType = FWP_MATCH_EQUAL;
        cond.conditionValue.type = FWP_UINT32;
        cond.conditionValue.uint32 = v4.S_un.S_addr;
    }
    else
    {
        memcpy(v6Bytes.byteArray16, v6.u.Byte, sizeof(v6Bytes.byteArray16));
        cond.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        cond.matchType = FWP_MATCH_EQUAL;
        cond.conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
        cond.conditionValue.byteArray16 = &v6Bytes;
    }

    std::wstring displayName = L"AntiAI block ";
    displayName += ipText;
    std::vector<wchar_t> displayNameBuf(displayName.begin(), displayName.end());
    displayNameBuf.push_back(L'\0');

    FWPM_FILTER0 filter{};
    filter.filterKey = filterKey;
    filter.displayData.name = displayNameBuf.data();
    filter.displayData.description =
        const_cast<PWSTR>(L"Educational deny on ALE_AUTH_CONNECT_* (remote IP equality)");
    filter.layerKey = isV4 ? FWPM_LAYER_ALE_AUTH_CONNECT_V4 : FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    filter.subLayerKey = ANTI_AI_WFP_SUBLAYER_KEY;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 15;
    filter.action.type = FWP_ACTION_BLOCK;
    filter.numFilterConditions = 1;
    filter.filterCondition = &cond;

    DWORD err = FwpmTransactionBegin0(g_engine, 0);
    if (err != ERROR_SUCCESS)
    {
        return HRESULT_FROM_WIN32(err);
    }

    err = FwpmFilterAdd0(g_engine, &filter, nullptr, nullptr);
    if (err != ERROR_SUCCESS)
    {
        FwpmTransactionAbort0(g_engine);
        return HRESULT_FROM_WIN32(err);
    }

    err = FwpmTransactionCommit0(g_engine);
    if (err != ERROR_SUCCESS)
    {
        FwpmTransactionAbort0(g_engine);
        return HRESULT_FROM_WIN32(err);
    }

    g_filterKeys.push_back(filterKey);
    return S_OK;
}

static void ClearBlockedIpsLocked()
{
    if (g_engine == nullptr)
    {
        g_filterKeys.clear();
        return;
    }

    for (const GUID &key : g_filterKeys)
    {
        DWORD err = FwpmTransactionBegin0(g_engine, 0);
        if (err != ERROR_SUCCESS)
        {
            continue;
        }

        err = FwpmFilterDeleteByKey0(g_engine, &key);
        if (err != ERROR_SUCCESS && err != static_cast<DWORD>(0x80320003u)) /* FWP_E_FILTER_NOT_FOUND */
        {
            FwpmTransactionAbort0(g_engine);
            continue;
        }

        err = FwpmTransactionCommit0(g_engine);
        if (err != ERROR_SUCCESS)
        {
            FwpmTransactionAbort0(g_engine);
        }
    }

    g_filterKeys.clear();
}

static void TryDeleteSublayerAndProviderLocked()
{
    if (g_engine == nullptr)
    {
        return;
    }

    DWORD err = FwpmTransactionBegin0(g_engine, 0);
    if (err != ERROR_SUCCESS)
    {
        return;
    }

    err = FwpmSubLayerDeleteByKey0(g_engine, &ANTI_AI_WFP_SUBLAYER_KEY);
    if (err != ERROR_SUCCESS && err != static_cast<DWORD>(0x80320007u)) /* FWP_E_SUBLAYER_NOT_FOUND */
    {
        FwpmTransactionAbort0(g_engine);
        return;
    }

    err = FwpmProviderDeleteByKey0(g_engine, &ANTI_AI_WFP_PROVIDER_KEY);
    if (err != ERROR_SUCCESS && err != static_cast<DWORD>(0x80320005u)) /* FWP_E_PROVIDER_NOT_FOUND */
    {
        FwpmTransactionAbort0(g_engine);
        return;
    }

    err = FwpmTransactionCommit0(g_engine);
    if (err != ERROR_SUCCESS)
    {
        FwpmTransactionAbort0(g_engine);
    }
}

} // namespace

HRESULT WfpBlacklistInit(void)
{
    std::lock_guard<std::recursive_mutex> guard(g_lock);
    return OpenEngineAndInstallPrimitivesLocked();
}

void WfpBlacklistShutdown(void)
{
    std::lock_guard<std::recursive_mutex> guard(g_lock);

    ClearBlockedIpsLocked();
    TryDeleteSublayerAndProviderLocked();

    if (g_engine != nullptr)
    {
        FwpmEngineClose0(g_engine);
        g_engine = nullptr;
    }

    if (g_wsaStarted)
    {
        WSACleanup();
        g_wsaStarted = false;
    }
}

HRESULT WfpAddBlockedIp(PCWSTR ipText)
{
    if (ipText == nullptr || ipText[0] == L'\0')
    {
        return E_INVALIDARG;
    }

    std::lock_guard<std::recursive_mutex> guard(g_lock);
    return AddBlockedIpLocked(ipText);
}

void WfpClearBlockedIps(void)
{
    std::lock_guard<std::recursive_mutex> guard(g_lock);
    ClearBlockedIpsLocked();
}

HRESULT WfpReloadBlacklistFromFile(PCWSTR fullPath)
{
    if (fullPath == nullptr || fullPath[0] == L'\0')
    {
        return E_INVALIDARG;
    }

    std::lock_guard<std::recursive_mutex> guard(g_lock);

    ClearBlockedIpsLocked();

    std::wifstream in(fullPath);
    if (!in)
    {
        return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
    }

    HRESULT firstFailure = S_OK;
    std::wstring line;
    while (std::getline(in, line))
    {
        TrimInPlace(line);
        if (line.empty() || line.front() == L'#')
        {
            continue;
        }

        const HRESULT hr = AddBlockedIpLocked(line.c_str());
        if (FAILED(hr) && SUCCEEDED(firstFailure))
        {
            firstFailure = hr;
        }
    }

    return firstFailure;
}
