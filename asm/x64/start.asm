;;
;; Captures incoming Net-NTLMv1/v2 hashes
;; for incoming authentication attempts 
;; via NTLM.
;; 
;; GuidePoint Security LLC
;; Threat and Attack Simulation
;;

GLOBAL	GetIp
GLOBAL	Leave
GLOBAL	Table

[SEGMENT .text$C]

Table:
	dq	0
	dq	0
	dq	0

[SEGMENT .text$F]

GetIp:
	;;
	;; Executes next instruction
	;;
	call	get_ret_ptr

	;;
	;; Returns pointer to itself
	;;
	get_ret_ptr:
	pop	rax
	sub	rax, 5
	ret

Leave:
	db 'E', 'N', 'D', 'O', 'F', 'C', 'O', 'D', 'E'
