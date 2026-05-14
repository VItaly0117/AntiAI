#pragma once

/*
 * Shared policy mode (kernel + AntiAIControl.exe).
 * AntiAIControl maps CLI subcommands to these values (IOCTL_ANTIAI_SET_MODE):
 *   mode off           -> ANTIAI_MODE_OFF
 *   mode audit         -> ANTIAI_MODE_AUDIT_ONLY
 *   mode block-network -> ANTIAI_MODE_BLOCK_NETWORK
 *   mode block-process -> ANTIAI_MODE_BLOCK_PROCESS
 *   mode block-all     -> ANTIAI_MODE_BLOCK_ALL
 */

#include <stdint.h>

typedef enum _ANTIAI_POLICY_MODE
{
    ANTIAI_MODE_OFF = 0,
    ANTIAI_MODE_AUDIT_ONLY = 1,
    ANTIAI_MODE_BLOCK_NETWORK = 2,
    ANTIAI_MODE_BLOCK_PROCESS = 3,
    ANTIAI_MODE_BLOCK_ALL = 4,
} ANTIAI_POLICY_MODE;
