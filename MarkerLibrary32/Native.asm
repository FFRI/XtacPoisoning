; (c) FFRI Security, Inc., 2023 / Author: FFRI Security, Inc.
.model flat, stdcall
.code

DllMain proc
	xor eax, eax
	call label7
	ret
label0:
	mov eax, 1
	ret
label1:
	call label0
	ret
label2:
	call label1
	ret
	ret
label3:
	call label2
	ret
	ret
	ret
label4:
	call label3
	ret
	ret
	ret
	ret
label5:
	call label4
	ret
	ret
	ret
	ret
	ret
label6:
	call label5
	ret
	ret
	ret
	ret
	ret
	ret
label7:
	call label6
	ret
DllMain endp

end