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

#if defined( _WIN64 )
#define G_END( x )	( ULONG_PTR )( GetIp() + 11 )
#else
#define G_END( x )	( ULONG_PTR )( GetIp() + 10 )
#endif

#define G_PTR( x )	( ULONG_PTR )( GetIp() - ( ( ULONG_PTR ) & GetIp - ( ULONG_PTR ) x ) )

/* Casts code to be stored in a specific section */
#define D_SEC( x )	__attribute__(( section( ".text$" #x "" ) ))

/* Create pointer with the specific typedef */
#define D_API( x )	__typeof__( x ) * x

/* Cast as a unsigned pointer-wide integer */
#define U_PTR( x )	( ( ULONG_PTR ) x )

/* Cast as a unsigned pointer */
#define C_PTR( x )	( ( PVOID ) x )
