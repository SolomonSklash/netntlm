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
);
