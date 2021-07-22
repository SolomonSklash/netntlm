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
 * @brief:	Hashes an input buffer of the specified length.
 *
 * @param:	Pointer to the start of the buffer.
 * @param:	Length of the buffer.
 *
**/

D_SEC( E ) ULONG HashString( _In_ PVOID Buffer, _In_ ULONG Length );
