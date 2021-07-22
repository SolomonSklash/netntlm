;;
;; Captures incoming Net-NTLMv1/v2 hashes
;; for incoming authentication attempts 
;; via NTLM.
;;
;; GuidePoint Security LLC
;; Threat and Attack Simulation
;;

[SEGMENT .text]

%ifidn __OUTPUT_FORMAT__, win32
	GLOBAL	_BofMain
	_BofMain:
	incbin "NetNtLmCapture.x86.bin"
%else
	GLOBAL BofMain
	BofMain:
	incbin "NetNtLmCapture.x64.bin"
%endif
