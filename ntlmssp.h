/*
 *   fs/cifs/ntlmssp.h
 *
 *   Copyright (c) International Business Machines  Corp., 2002,2007
 *   Author(s): Steve French (sfrench@us.ibm.com)
 *
 *   This library is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU Lesser General Public License as published
 *   by the Free Software Foundation; either version 2.1 of the License, or
 *   (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public License
 *   along with this library; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#define NTLMSSP_SIGNATURE "NTLMSSP"
/* Message Types */
#define NtLmNegotiate     cpu_to_le32(1)
#define NtLmChallenge     cpu_to_le32(2)
#define NtLmAuthenticate  cpu_to_le32(3)
#define UnknownMessage    cpu_to_le32(8)

/* Negotiate Flags */
#define NTLMSSP_NEGOTIATE_UNICODE         0x01 /* Text strings are unicode */
#define NTLMSSP_NEGOTIATE_OEM             0x02 /* Text strings are in OEM */
#define NTLMSSP_REQUEST_TARGET            0x04 /* Srv returns its auth realm */
/* define reserved9                       0x08 */
#define NTLMSSP_NEGOTIATE_SIGN          0x0010 /* Request signing capability */
#define NTLMSSP_NEGOTIATE_SEAL          0x0020 /* Request confidentiality */
#define NTLMSSP_NEGOTIATE_DGRAM         0x0040
#define NTLMSSP_NEGOTIATE_LM_KEY        0x0080 /* Use LM session key */
/* defined reserved 8                   0x0100 */
#define NTLMSSP_NEGOTIATE_NTLM          0x0200 /* NTLM authentication */
#define NTLMSSP_NEGOTIATE_NT_ONLY       0x0400 /* Lanman not allowed */
#define NTLMSSP_ANONYMOUS               0x0800
#define NTLMSSP_NEGOTIATE_DOMAIN_SUPPLIED 0x1000 /* reserved6 */
#define NTLMSSP_NEGOTIATE_WORKSTATION_SUPPLIED 0x2000
#define NTLMSSP_NEGOTIATE_LOCAL_CALL    0x4000 /* client/server same machine */
#define NTLMSSP_NEGOTIATE_ALWAYS_SIGN   0x8000 /* Sign. All security levels  */
#define NTLMSSP_TARGET_TYPE_DOMAIN     0x10000
#define NTLMSSP_TARGET_TYPE_SERVER     0x20000
#define NTLMSSP_TARGET_TYPE_SHARE      0x40000
#define NTLMSSP_NEGOTIATE_EXTENDED_SEC 0x80000 /* NB:not related to NTLMv2 pwd*/
/* #define NTLMSSP_REQUEST_INIT_RESP     0x100000 */
#define NTLMSSP_NEGOTIATE_IDENTIFY    0x100000
#define NTLMSSP_REQUEST_ACCEPT_RESP   0x200000 /* reserved5 */
#define NTLMSSP_REQUEST_NON_NT_KEY    0x400000
#define NTLMSSP_NEGOTIATE_TARGET_INFO 0x800000
/* #define reserved4                 0x1000000 */
#define NTLMSSP_NEGOTIATE_VERSION    0x2000000 /* we do not set */
/* #define reserved3                 0x4000000 */
/* #define reserved2                 0x8000000 */
/* #define reserved1                0x10000000 */
#define NTLMSSP_NEGOTIATE_128       0x20000000
#define NTLMSSP_NEGOTIATE_KEY_XCH   0x40000000
#define NTLMSSP_NEGOTIATE_56        0x80000000

/* Although typedefs are not commonly used for structure definitions */
/* in the Linux kernel, in this particular case they are useful      */
/* to more closely match the standards document for NTLMSSP from     */
/* OpenGroup and to make the code more closely match the standard in */
/* appearance */

typedef struct _SECURITY_BUFFER {
	UINT16 Length;
	UINT16 MaximumLength;
	UINT32 BufferOffset;	/* offset to buffer */
} __attribute__((packed)) SECURITY_BUFFER;

typedef struct _AUTHENTICATE_MESSAGE {
	UINT8 Signature[sizeof(NTLMSSP_SIGNATURE)];
	UINT32 MessageType;  /* NtLmsAuthenticate = 3 */
	SECURITY_BUFFER LmChallengeResponse;
	SECURITY_BUFFER NtChallengeResponse;
	SECURITY_BUFFER DomainName;
	SECURITY_BUFFER UserName;
	SECURITY_BUFFER WorkstationName;
	SECURITY_BUFFER SessionKey;
	UINT32 NegotiateFlags;
} __attribute__((packed)) AUTHENTICATE_MESSAGE, *PAUTHENTICATE_MESSAGE;
