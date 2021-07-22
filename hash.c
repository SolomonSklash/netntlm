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
 * @brief:      Hashes an input buffer of the specified length.
 *
 * @param:      Pointer to the start of the buffer.
 * @param:      Length of the buffer.
 *
**/

D_SEC( E ) ULONG HashString( _In_ PVOID Buffer, _In_ ULONG Length )
{
	UCHAR	Chr = 0 ;
	UINT32	Djb = 0 ;
	PUCHAR	Ptr = NULL ;

	Djb = 5381;
	Ptr = Buffer;

	while ( TRUE ) {
		/* Parse the current character */
		Chr = * Ptr;

		/* \0 terminated? */
		if ( ! Length ) {
			if ( ! * Ptr ) {
				break;
			};
		} else {
			/* End of string? */
			if ( ( ULONG )( Ptr - ( PUCHAR ) Buffer ) >= Length ) {
				break;
			};
			/* Not null? Next! */
			if ( ! * Ptr ) {
				++Ptr; continue;
			};
		};

		/* Uppercase */
		if ( Chr >= 'a' ) {
			Chr -= 0x20 ;
		};

		/* Create hash */
		Djb = ( ( Djb << 5 ) + Djb ) + Chr; Ptr++;
	};
	return Djb;
};
