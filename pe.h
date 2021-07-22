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
 * @brief:	Acts a replacement for GetProcAddress
 *
 * @param:	Pointer to the PE base.
 * @param:	Hash of the function name.
 *
**/

D_SEC( E ) PVOID PeGetFuncEat( _In_ PVOID Image, _In_ ULONG ExpHash );
