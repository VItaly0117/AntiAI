#pragma once

/*
 * IOCTL contract for AntiAIKernel (KMDF) and AntiAIControl.exe (user mode).
 * All listed IOCTLs use METHOD_BUFFERED.
 */

#include "antiai_policy.h"

#if defined(_KERNEL_MODE)
#include <wdm.h>
#include <wdf.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif

/* Vendor-defined device type (custom range; avoid well-known FILE_DEVICE_* collisions). */
#define ANTIAI_DEVICE_TYPE 0x8100u

#define ANTIAI_CTL_CODE(Function) \
    CTL_CODE(ANTIAI_DEVICE_TYPE, (Function), METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_ANTIAI_PING        ANTIAI_CTL_CODE(0x800)
#define IOCTL_ANTIAI_GET_VERSION ANTIAI_CTL_CODE(0x801)
#define IOCTL_ANTIAI_GET_STATUS  ANTIAI_CTL_CODE(0x802)
#define IOCTL_ANTIAI_SET_MODE    ANTIAI_CTL_CODE(0x803)
#define IOCTL_ANTIAI_GET_MODE    ANTIAI_CTL_CODE(0x804)

/*
 * Kernel exposes symbolic link \DosDevices\AntiAIKernel -> user opens:
 */
#define ANTIAI_USER_DEVICE_PATH L"\\\\.\\AntiAIKernel"

typedef struct _ANTIAI_SET_MODE_IN
{
    ANTIAI_POLICY_MODE Mode;
} ANTIAI_SET_MODE_IN, *PANTIAI_SET_MODE_IN;

typedef struct _ANTIAI_GET_MODE_OUT
{
    ANTIAI_POLICY_MODE Mode;
} ANTIAI_GET_MODE_OUT, *PANTIAI_GET_MODE_OUT;

typedef struct _ANTIAI_GET_VERSION_OUT
{
    UINT16 Major;
    UINT16 Minor;
    UINT32 Build;
} ANTIAI_GET_VERSION_OUT, *PANTIAI_GET_VERSION_OUT;

typedef struct _ANTIAI_GET_STATUS_OUT
{
    ANTIAI_POLICY_MODE PolicyMode;
    UINT32 Flags;
    UINT32 Reserved0;
    UINT32 Reserved1;
} ANTIAI_GET_STATUS_OUT, *PANTIAI_GET_STATUS_OUT;
