; Adapted to work along with C calls
; by Geovandro C. C. F. Pereira
	
	
;;; ***************************************************************************
;;; The Rijndael cipher acts on a so-called (128 bit) "state matrix", 
;;; represented here by the 4x4 state bytes ST11-ST44. To guarantee maximum
;;; performance on AVR MCUs, these bytes are kept in registers (defaulted to
;;; the 16 low order registers r0-r15, but this may be changed if required).
;;; 
;;; The implementation makes use of six auxiliary registers (H1-H5 and I),
;;; some of which must reside in the upper registers (r16-r31). In addition
;;; ramp-registers YH:YL and r31:r30 are used.
;;;
;;; If the context *really* requires more registers than the remaining ones, 
;;; it seems promising to move the I-register to a (fixed) ram location. 
;;; In the time crititcal routines the I-value is rarely used, thus the 
;;; speed loss obtained by dropping it from the register file is acceptible. 

		
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

;;; ***************************************************************************
;;; 
;;; ENCRYPT 
;;; This routine encrypts a 128 bit plaintext block (supplied in ST11-ST44), 
;;; using an expanded key given in YH:YL. The resulting 128 bit ciphertext
;;; block is stored in ST11-ST44.
;;;
;;; Parameters:
;;;         YH:YL:	pointer to expanded key
;;;         ST11-ST44:  128 bit plaintext block
;;; Touched registers:
;;;     ST11-ST41,H1-H5,I,r31,r30,YH,YL
;;; Clock cycles:	XXXX
;;; aes128_enc(void* plaintext, aes128_ctx_t* aes128_ctx);
;;; r24:r25 <= plaintext
;;; r22:r23 <= aes128_ctx

.global aes128_enc
aes128_enc:

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
	//push r18
	//push r19
	//push r20
	//push r21
	push r28
	push r29

	movw r30, r24 //Z <- plaintext
	movw r26, r24 //X <- plaintext
	movw r28, r22 //Y <- aes_roundkey_ctx

	.irp index, ST11,ST21,ST31,ST41, ST12,ST22,ST32,ST42, ST13,ST23,ST33,ST43, ST14,ST24,ST34,ST44
		ld \index, Z+
	.endr
	//; now the registers ST11-ST44 contain the plaintext
	
	rcall encryp1
	ldi r31, hi8(sbox)
	ldi I, 8
encryp0:mov r30, ST11		; 1
	lpm H2, Z
	mov H3, H2
	mov H4, H2
	ldi r31, hi8(sbox02)
	lpm H1, Z
	eor H4, H1
	mov r30, ST22
	lpm H5, Z
	eor H1, H5
	eor H2, H5
	ldi r31, hi8(sbox)
	lpm H5, Z
	eor H1, H5
	eor H3, H5
	eor H4, H5
	mov r30, ST33
	lpm H5, Z
	eor H1, H5
	eor H2, H5
	eor H4, H5
	ldi r31, hi8(sbox02)
	lpm H5, Z
	eor H2, H5
	eor H3, H5
	mov r30, ST44
	lpm H5, Z
	eor H3, H5
	eor H4, H5
	ldi r31, hi8(sbox)
	lpm H5, Z
	eor H1, H5
	eor H2, H5
	eor H3, H5
	ldd ST11, Y+0
	eor ST11, H1
	mov r30, ST41		; 2
	ldd ST41, Y+3
	eor ST41, H4
	lpm H1, Z
	mov H4, H1
	mov ST33, H1
	ldi r31, hi8(sbox02)
	lpm ST44, Z
	eor ST33, ST44
	mov r30, ST12
	lpm H5, Z
	eor H1, H5
	eor ST44, H5
	ldi r31, hi8(sbox)
	lpm H5, Z
	eor H4, H5
	eor ST33, H5
	eor ST44, H5
	mov r30, ST23
	lpm H5, Z
	eor H1, H5
	eor ST33, H5
	eor ST44, H5
	ldi r31, hi8(sbox02)
	lpm H5, Z
	eor H1, H5
	eor H4, H5
	mov r30, ST34
	lpm H5, Z
	eor H4, H5
	eor ST33, H5
	ldi r31, hi8(sbox)
	lpm H5, Z
	eor H1, H5
	eor H4, H5
	eor ST44, H5
	ldd ST12, Y+4
	eor ST12, H1
	ldd ST22, Y+5
	eor ST22, H4
	mov r30, ST31		; 3
	ldd ST31, Y+2
	eor ST31, H3
	lpm ST34, Z
	mov H3, ST34
	mov H1, ST34
	ldi r31, hi8(sbox02)
	lpm H4, Z
	eor H3, H4
	mov r30, ST42
	ldd ST42, Y+7
	eor ST42, ST44
	lpm H5, Z
	eor H4, H5
	eor H1, H5
	ldi r31, hi8(sbox)
	lpm H5, Z
	eor ST34, H5
	eor H3, H5
	eor H4, H5
	mov r30, ST13
	lpm H5, Z
	eor H3, H5
	eor H4, H5
	eor H1, H5
	ldi r31, hi8(sbox02)
	lpm H5, Z
	eor ST34, H5
	eor H1, H5
	mov r30, ST24
	lpm H5, Z
	eor ST34, H5
	eor H3, H5
	ldi r31, hi8(sbox)
	lpm H5, Z
	eor ST34, H5
	eor H4, H5
	eor H1, H5
	ldd ST13, Y+8
	eor ST13, ST34
	ldd ST23, Y+9
	eor ST23, H3
	mov r30, ST32		; 4
	ldd ST32, Y+6
	eor ST32, ST33
	ldd ST33, Y+10
	eor ST33, H4
	lpm ST24, Z
	mov ST34, ST24
	mov H4, ST24
	ldi r31, hi8(sbox02)
	lpm H3, Z
	eor ST34, H3
	mov r30, ST43
	ldd ST43, Y+11
	eor ST43, H1
	lpm H5, Z
	eor H3, H5
	eor H4, H5
	ldi r31, hi8(sbox)
	lpm H5, Z
	eor ST24, H5
	eor ST34, H5
	eor H3, H5
	mov r30, ST14
	lpm H5, Z
	eor ST34, H5
	eor H3, H5
	eor H4, H5
	ldi r31, hi8(sbox02)
	lpm H5, Z
	eor ST24, H5
	eor H4, H5
	mov r30, ST21
	lpm H5, Z
	eor ST24, H5
	eor ST34, H5
	ldi r31, hi8(sbox)
	lpm H5, Z
	eor ST24, H5
	eor H3, H5
	eor H4, H5
	ldd ST21, Y+1
	eor ST21, H2
	ldd ST14, Y+12
	eor ST14, ST24
	ldd ST24, Y+13
	eor ST24, ST34
	ldd ST34, Y+14
	eor ST34, H3
	ldd ST44, Y+15
	eor ST44, H4
	adiw r28, 16
	dec I
	sbrs I,7
	jmp encryp0
	mov r30, ST11
	lpm ST11, Z
	mov r30, ST12
	lpm ST12, Z
	mov r30, ST13
	lpm ST13, Z
	mov r30, ST14
	lpm ST14, Z
	mov H1, ST21
	mov r30, ST22
	lpm ST21, Z
	mov r30, ST23
	lpm ST22, Z
	mov r30, ST24
	lpm ST23, Z
	mov r30, H1
	lpm ST24, Z
	mov H1, ST31
	mov r30, ST33
	lpm ST31, Z
	mov r30, H1
	lpm ST33, Z
	mov H1, ST32
	mov r30, ST34
	lpm ST32, Z
	mov r30, H1
	lpm ST34, Z
	mov H1, ST41
	mov r30, ST44
	lpm ST41, Z
	mov r30, ST43
	lpm ST44, Z
	mov r30, ST42
	lpm ST43, Z
	mov r30, H1
	lpm ST42, Z
encryp2:ld H1, Y+
	eor ST11, H1
	ld H1, Y+
	eor ST21, H1
	ld H1, Y+
	eor ST31, H1
	ld H1, Y+
	eor ST41, H1
	ld H1, Y+
	eor ST12, H1
	ld H1, Y+
	eor ST22, H1
	ld H1, Y+
	eor ST32, H1
	ld H1, Y+
	eor ST42, H1
	ld H1, Y+
	eor ST13, H1
	ld H1, Y+
	eor ST23, H1
	ld H1, Y+
	eor ST33, H1
	ld H1, Y+
	eor ST43, H1
	ld H1, Y+
	eor ST14, H1
	ld H1, Y+
	eor ST24, H1
	ld H1, Y+
	eor ST34, H1
	ld H1, Y+
	eor ST44, H1

	st X+, ST11
	st X+, ST21
	st X+, ST31
	st X+, ST41
	st X+, ST12
	st X+, ST22
	st X+, ST32
	st X+, ST42
	st X+, ST13
	st X+, ST23
	st X+, ST33
	st X+, ST43
	st X+, ST14
	st X+, ST24
	st X+, ST34
	st X+, ST44

	pop r29
	pop r28
	//pop r21
	//pop r20
	//pop r19
	//pop r18
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
encryp1:ld H1, Y+
	eor ST11, H1
	ld H1, Y+
	eor ST21, H1
	ld H1, Y+
	eor ST31, H1
	ld H1, Y+
	eor ST41, H1
	ld H1, Y+
	eor ST12, H1
	ld H1, Y+
	eor ST22, H1
	ld H1, Y+
	eor ST32, H1
	ld H1, Y+
	eor ST42, H1
	ld H1, Y+
	eor ST13, H1
	ld H1, Y+
	eor ST23, H1
	ld H1, Y+
	eor ST33, H1
	ld H1, Y+
	eor ST43, H1
	ld H1, Y+
	eor ST14, H1
	ld H1, Y+
	eor ST24, H1
	ld H1, Y+
	eor ST34, H1
	ld H1, Y+
	eor ST44, H1

	ret


