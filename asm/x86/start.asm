;;
;; Captures incoming Net-NTLMv1/v2 hashes
;; for incoming authentication attempts 
;; via NTLM.
;; 
;; GuidePoint Security LLC
;; Threat and Attack Simulation
;;

GLOBAL	_GetIp
GLOBAL	_Leave
GLOBAL	_Table

[SEGMENT .text$C]

_Table:
	dd	0
	dd	0
	dd	0

[SEGMENT .text$F]

_GetIp:
	;;
	;; Executes next instruction
	;;
	call	_get_ret_ptr

	;;
	;; Returns pointer to itself
	;;
	_get_ret_ptr:
	pop	eax
	sub	eax, 5
	ret

_Leave:
	db 'E', 'N', 'D', 'O', 'F', 'C', 'O', 'D', 'E'
