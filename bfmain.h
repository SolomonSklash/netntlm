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

#include "common.h"

/**
 *
 * @brief:	Searches for Lsa and injects itself.
 *
 * @param:	Pointer to the virtual method table.
 * @param:	Argument array from Cobalt Strike.
 * @param:	Argument length from Cobalt Strike.
 *
**/
D_SEC( A ) VOID WINAPI BofMain( _In_ PBAPI_TABLE BeaconApi, _In_ PVOID Argv, _In_ INT Argc );
