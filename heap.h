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

/**
 *
 * @brief:	Checks if the region is a heap pointer.
 *
 * @param:	Pointer to the API structure.
 * @param:	Pointer.
 *
**/

D_SEC( E ) BOOL IsHeapPtr( _In_ PAPI Api, _In_ PVOID Heap, _Out_ PULONG Len );
