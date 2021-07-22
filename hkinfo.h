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

typedef struct __attribute__(( packed )) {
	HANDLE	                   BeaconLog;
	PSECPKG_FUNCTION_TABLE	   SecurityPackage;
	SpAcceptLsaModeContextFn * AcceptLsaModeContext;
} HKINFO, *PHKINFO ;
