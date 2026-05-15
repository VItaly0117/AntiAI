#pragma once

/*
 * AntiAI process_guard — educational process-create notify (test VM only).
 *
 * INTEGRATION (AntiAIKernel / Driver.c):
 *   1) After successful WdfDriverCreate in DriverEntry, call ProcessGuardInitialize().
 *      If it fails, return that NTSTATUS from DriverEntry (framework tears down WDF).
 *   2) Register WDF_DRIVER_CONFIG.EvtDriverUnload = AntiAIEvtDriverUnload and call
 *      ProcessGuardShutdown() from that unload path (PASSIVE_LEVEL).
 *   3) Whenever IOCTL_ANTIAI_SET_MODE commits a new ANTIAI_POLICY_MODE, call
 *      ProcessGuardSetPolicyMode(mode) so the notify callback sees the latest policy.
 *
 * POLICY (MVP):
 *   - OFF / BLOCK_NETWORK: callback returns immediately (no process deny in this module).
 *   - AUDIT_ONLY: if exact image filename matches demo denylist, KdPrintEx only (never deny).
 *   - BLOCK_PROCESS / BLOCK_ALL: deny creation for exact image filename fake_ai_tool.exe or ollama.exe.
 *   - python.exe is never blocked or audit-logged here.
 *   - Paths under \\Windows\\System32\\ and \\Windows\\SysWOW64\\ are ignored (system churn).
 *
 * STABILITY / SAFETY WARNINGS (read before enabling outside a throwaway VM):
 *   - PsSetCreateProcessNotifyRoutineEx runs with high frequency; keep O(1) work, no
 *     blocking waits, no paged memory touches that can fault at elevated IRQL paths.
 *   - Unregister the notify routine from driver unload before releasing other globals;
 *     a lingering callback after unload is a bugcheck risk.
 *   - ImageFileName is kernel-valid in this callback; CommandLine can be user-supplied /
 *     optional — this MVP does not parse CommandLine (add only with strict validation).
 *   - Over-broad deny rules can brick automation or installers; keep the denylist tiny.
 *   - PatchGuard / signing / policy: notify routines require a compliant driver package;
 *     use test signing on lab VMs only.
 */

#include <ntddk.h>

#include "antiai_policy.h"

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS ProcessGuardInitialize(void);

_IRQL_requires_max_(PASSIVE_LEVEL)
void ProcessGuardShutdown(void);

void ProcessGuardSetPolicyMode(_In_ ANTIAI_POLICY_MODE mode);
