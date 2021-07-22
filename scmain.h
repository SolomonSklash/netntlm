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
 * @brief:	Installs a hook on Lsa's SECPKG_FUNCTION_TABLE
 *
 * @param:	Pointer to a pipe name.
 *
**/

D_SEC( B ) VOID WINAPI InstallHook( _In_ LPVOID Parameter );
