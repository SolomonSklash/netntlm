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

typedef struct {
	D_API( CreateToolhelp32Snapshot );
	D_API( CreateNamedPipeA );
	D_API( ConnectNamedPipe );
	D_API( SpInitializeFn );
	D_API( Process32First );
	D_API( Process32Next );
	D_API( VirtualAlloc );
	D_API( VirtualFree );
	D_API( CloseHandle );
	D_API( OpenProcess );
	D_API( LocalAlloc );
	D_API( HeapUnlock );
	D_API( WriteFile );
	D_API( LocalFree );
	D_API( vsnprintf );
	D_API( HeapLock );
	D_API( HeapWalk );
} API, *PAPI ;
