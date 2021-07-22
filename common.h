/**
 *
 * Captures incoming Net-NTLMv1/v2 hashes
 * for incoming authentication attempts 
 * via NTLM.
 *
 * GuidePoint Security LLC
 * Threat and Attack Simulation
 *
**/

#pragma once

#define SECURITY_WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <ntstatus.h>
#include <sspi.h>
#include <ntsecpkg.h>
#include <stdio.h>
#include <stdarg.h>
#include "macros.h"
#include "labels.h"
#include "tebpeb.h"
#include "hashes.h"
#include "bapi.h"
#include "hash.h"
#include "peb.h"
#include "api.h"
#include "pe.h"


#include "ntlmssp.h"
#include "bfmain.h"
#include "scmain.h"
#include "hkmain.h"
#include "hkinfo.h"
#include "pipe.h"
#include "heap.h"
