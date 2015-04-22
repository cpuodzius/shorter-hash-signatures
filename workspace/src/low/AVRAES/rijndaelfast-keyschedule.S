; author: Geovandro C. C. F. Pereira


ST11 = 0//r0
ST21 = 1//r1
ST31 = 2//r2
ST41 = 3//r3
ST12 = 4//r4
ST22 = 5//r5
ST32 = 6//r6
ST42 = 7//r7
ST13 = 8//r8
ST23 = 9//r9
ST33 =10//r10
ST43 =11//r11
ST14 =12//r12
ST24 =13//r13
ST34 =14//r14
ST44 =15//r15
H1   =16//r16
H2   =17//r17
H3   =18//r18
H4   =19//r19
H5   =20//r20
I    =21//r21


; Parameters aes128_init(const void* key, aes128_ctx_t* aes128_ctx)
; r22:r23 <= aes128_ctx
; r24:r25 <= key

.global aes128_init
aes128_init:	

	push r1
	push r2
	push r3
	push r4
	push r5
	push r6
	push r7
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
	push r16
	push r17
	push r28
	push r29


	movw r28, r22 //Y <- ctx

	// load key into ST11-ST44
	movw r30, r24 //Z <- key
	.irp index, ST11,ST21,ST31,ST41, ST12,ST22,ST32,ST42, ST13,ST23,ST33,ST43, ST14,ST24,ST34,ST44
		ld \index, Z+
	.endr

	rcall key_expand

	pop r29
	pop r28
	pop r17
	pop r16
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop r7
	pop r6
	pop r5
	pop r4
	pop r3
	pop r2
	pop r1

	ret

;;; ***************************************************************************
;;; 
;;; KEY_EXPAND
;;; The caller supplies the 128 bit key in the registers ST11-ST44 and a pointer 
;;; in the YH:YL register pair. The key is expanded to the memory 
;;; positions [Y : Y+16*11-1]. Note: the key expansion is necessary for both
;;; encryption and decryption.
;;; 
;;; Parameters:
;;;     ST11-ST44:	the 128 bit key
;;;         YH:YL:	pointer to ram location
;;; Touched registers:
;;;     ST11-ST44,H1-H3,ZH,ZL,YH,YL
;;; Clock cycles:	756
;;; Made this global, Geovandro

key_expand:
	ldi H1, 1
	ldi H2, 0x1b
	ldi r31, hi8(sbox) //ZH <- sbox
	rjmp keyexp1
keyexp0:mov r30, ST24
	lpm H3, Z
	eor ST11, H3
	eor ST11, H1
	mov r30, ST34
	lpm H3, Z
	eor ST21, H3
	mov r30, ST44
	lpm H3, Z
	eor ST31, H3
	mov r30, ST14
	lpm H3, Z
	eor ST41, H3
	eor ST12, ST11
	eor ST22, ST21
	eor ST32, ST31
	eor ST42, ST41
	eor ST13, ST12
	eor ST23, ST22
	eor ST33, ST32
	eor ST43, ST42
	eor ST14, ST13
	eor ST24, ST23
	eor ST34, ST33
	eor ST44, ST43
	lsl H1
	brcc keyexp1
	eor H1, H2
keyexp1:st Y+, ST11
	st Y+, ST21
	st Y+, ST31
	st Y+, ST41
	st Y+, ST12
	st Y+, ST22
	st Y+, ST32
	st Y+, ST42
	st Y+, ST13
	st Y+, ST23
	st Y+, ST33
	st Y+, ST43
	st Y+, ST14
	st Y+, ST24
	st Y+, ST34
	st Y+, ST44
	cpi H1, 0x6c //if H1 != 0x6C then go to keyexp0
	brne keyexp0 //

	ret

