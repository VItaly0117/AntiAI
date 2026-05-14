#pragma once

/*
 * AntiAIWfp — educational user-mode outbound IP deny via Windows Filtering Platform (WFP).
 *
 * WFP layer choice (outbound IPv4 / IPv6):
 *   Use FWPM_LAYER_ALE_AUTH_CONNECT_V4 / FWPM_LAYER_ALE_AUTH_CONNECT_V6.
 *   These ALE "authorize connect" layers run when the stack is deciding whether an
 *   outbound connection to a remote endpoint may proceed. A terminating BLOCK action
 *   denies the connect without packet injection, proxying, or TLS interception.
 *
 * MVP limitations (read before relying on this in a lab):
 *   - CDN / anycast: a hostname resolves to many addresses; blocking one IP rarely
 *     blocks "the whole site", and traffic may shift to other edges.
 *   - Dynamic DNS: IPs change; your blacklist becomes stale until refreshed.
 *   - DNS-over-HTTPS (DoH) / encrypted DNS: the OS may still resolve elsewhere; this
 *     code only filters transport connects, not DNS queries themselves.
 *   - IPv6: supported only when you add IPv6 literals; AAAA-heavy sites may bypass
 *     IPv4-only blocks unless you also block IPv6 endpoints.
 *   - Admin rights: modifying the BFE database requires elevation.
 *   - Scope: outbound remote IP equality match only — no TLS MITM, no stealth.
 *
 * Example — block one resolved IPv4 for chatgpt.com (lab only):
 *   1) nslookup chatgpt.com
 *   2) Pick an A record (note CDN caveat above).
 *   3) AntiAIControl.exe add-ip 104.18.xx.xx   (example only; your lookup will differ)
 *
 * Pseudocode for engine/provider/sublayer/filter (what wfp_blocklist.cpp does):
 *   FwpmEngineOpen0(nullptr, ...);
 *   FwpmTransactionBegin0(engine);
 *   FwpmProviderAdd0(engine, &providerWithOurGuid);      // idempotent if exists
 *   FwpmSubLayerAdd0(engine, &subLayerUnderThatProvider); // idempotent if exists
 *   FwpmFilterAdd0(engine, &filterBlockRemoteIpOnAleAuthConnectVx);
 *   FwpmTransactionCommit0(engine);
 */

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

HRESULT WfpBlacklistInit(void);
void WfpBlacklistShutdown(void);

HRESULT WfpAddBlockedIp(PCWSTR ipText);
void WfpClearBlockedIps(void);

/* Clears existing WFP filters from this module, then adds one line per IP (# comments). */
HRESULT WfpReloadBlacklistFromFile(PCWSTR fullPath);

#ifdef __cplusplus
} // extern "C"
#endif
