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
 * @brief:	Create a named pipe server.
 *
 * @param:	API table.
 * @param:	PIpe name.
 *
**/
D_SEC( E ) HANDLE PipeInit( _In_ PAPI Api, _In_ PCHAR Name );

/**
 *
 * @brief:	Waits for a connection from a client.
 *
 * @param:	Pointer to API structure.
 * @param:	Pointer to a pipe handle.
 *
**/

D_SEC( E ) BOOL PipeWait( _In_ PAPI Api, _In_ HANDLE Pipe );

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

D_SEC( E ) BOOL PipePrint( _In_ PAPI Api, _In_ HANDLE Pipe, _In_ PCHAR Format, ... );
