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
 * @brief:	Acts as a replacement for GetModuleHandle.
 *
 * @param:	Hash of the module name.
 *
**/

D_SEC( E ) PVOID PebGetModule( _In_ ULONG ModHash );
