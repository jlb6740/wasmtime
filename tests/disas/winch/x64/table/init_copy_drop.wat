;;! target = "x86_64"
;;! test = "winch"

(module
  (type (func (result i32)))  ;; type #0
  (import "a" "ef0" (func (result i32)))    ;; index 0
  (import "a" "ef1" (func (result i32)))
  (import "a" "ef2" (func (result i32)))
  (import "a" "ef3" (func (result i32)))
  (import "a" "ef4" (func (result i32)))    ;; index 4
  (table $t0 30 30 funcref)
  (table $t1 30 30 funcref)
  (elem (table $t0) (i32.const 2) func 3 1 4 1)
  (elem funcref
    (ref.func 2) (ref.func 7) (ref.func 1) (ref.func 8))
  (elem (table $t0) (i32.const 12) func 7 5 2 3 6)
  (elem funcref
    (ref.func 5) (ref.func 9) (ref.func 2) (ref.func 7) (ref.func 6))
  (func (result i32) (i32.const 5))  ;; index 5
  (func (result i32) (i32.const 6))
  (func (result i32) (i32.const 7))
  (func (result i32) (i32.const 8))
  (func (result i32) (i32.const 9))  ;; index 9
  (func (export "test")
    (table.init $t0 1 (i32.const 7) (i32.const 0) (i32.const 4))
         (elem.drop 1)
         (table.init $t0 3 (i32.const 15) (i32.const 1) (i32.const 3))
         (elem.drop 3)
         (table.copy $t0 0 (i32.const 20) (i32.const 15) (i32.const 5))
         (table.copy $t0 0 (i32.const 21) (i32.const 29) (i32.const 1))
         (table.copy $t0 0 (i32.const 24) (i32.const 10) (i32.const 1))
         (table.copy $t0 0 (i32.const 13) (i32.const 11) (i32.const 4))
         (table.copy $t0 0 (i32.const 19) (i32.const 20) (i32.const 5)))
  (func (export "check") (param i32) (result i32)
    (call_indirect $t0 (type 0) (local.get 0)))
)
;; wasm[0]::function[5]:
;;       pushq   %rbp
;;       movq    %rsp, %rbp
;;       movq    8(%rdi), %r11
;;       movq    0x10(%r11), %r11
;;       addq    $0x10, %r11
;;       cmpq    %rsp, %r11
;;       ja      0x3d
;;   1c: movq    %rdi, %r14
;;       subq    $0x10, %rsp
;;       movq    %rdi, 8(%rsp)
;;       movq    %rsi, (%rsp)
;;       movl    $5, %eax
;;       addq    $0x10, %rsp
;;       popq    %rbp
;;       retq
;;   3d: ud2
;;
;; wasm[0]::function[6]:
;;       pushq   %rbp
;;       movq    %rsp, %rbp
;;       movq    8(%rdi), %r11
;;       movq    0x10(%r11), %r11
;;       addq    $0x10, %r11
;;       cmpq    %rsp, %r11
;;       ja      0x7d
;;   5c: movq    %rdi, %r14
;;       subq    $0x10, %rsp
;;       movq    %rdi, 8(%rsp)
;;       movq    %rsi, (%rsp)
;;       movl    $6, %eax
;;       addq    $0x10, %rsp
;;       popq    %rbp
;;       retq
;;   7d: ud2
;;
;; wasm[0]::function[7]:
;;       pushq   %rbp
;;       movq    %rsp, %rbp
;;       movq    8(%rdi), %r11
;;       movq    0x10(%r11), %r11
;;       addq    $0x10, %r11
;;       cmpq    %rsp, %r11
;;       ja      0xbd
;;   9c: movq    %rdi, %r14
;;       subq    $0x10, %rsp
;;       movq    %rdi, 8(%rsp)
;;       movq    %rsi, (%rsp)
;;       movl    $7, %eax
;;       addq    $0x10, %rsp
;;       popq    %rbp
;;       retq
;;   bd: ud2
;;
;; wasm[0]::function[8]:
;;       pushq   %rbp
;;       movq    %rsp, %rbp
;;       movq    8(%rdi), %r11
;;       movq    0x10(%r11), %r11
;;       addq    $0x10, %r11
;;       cmpq    %rsp, %r11
;;       ja      0xfd
;;   dc: movq    %rdi, %r14
;;       subq    $0x10, %rsp
;;       movq    %rdi, 8(%rsp)
;;       movq    %rsi, (%rsp)
;;       movl    $8, %eax
;;       addq    $0x10, %rsp
;;       popq    %rbp
;;       retq
;;   fd: ud2
;;
;; wasm[0]::function[9]:
;;       pushq   %rbp
;;       movq    %rsp, %rbp
;;       movq    8(%rdi), %r11
;;       movq    0x10(%r11), %r11
;;       addq    $0x10, %r11
;;       cmpq    %rsp, %r11
;;       ja      0x13d
;;  11c: movq    %rdi, %r14
;;       subq    $0x10, %rsp
;;       movq    %rdi, 8(%rsp)
;;       movq    %rsi, (%rsp)
;;       movl    $9, %eax
;;       addq    $0x10, %rsp
;;       popq    %rbp
;;       retq
;;  13d: ud2
;;
;; wasm[0]::function[10]:
;;       pushq   %rbp
;;       movq    %rsp, %rbp
;;       movq    8(%rdi), %r11
;;       movq    0x10(%r11), %r11
;;       addq    $0x10, %r11
;;       cmpq    %rsp, %r11
;;       ja      0x2b4
;;  15c: movq    %rdi, %r14
;;       subq    $0x10, %rsp
;;       movq    %rdi, 8(%rsp)
;;       movq    %rsi, (%rsp)
;;       movq    %r14, %rdi
;;       movl    $0, %esi
;;       movl    $1, %edx
;;       movl    $7, %ecx
;;       movl    $0, %r8d
;;       movl    $4, %r9d
;;       callq   0x8a7
;;       movq    8(%rsp), %r14
;;       movq    %r14, %rdi
;;       movl    $1, %esi
;;       callq   0x905
;;       movq    8(%rsp), %r14
;;       movq    %r14, %rdi
;;       movl    $0, %esi
;;       movl    $3, %edx
;;       movl    $0xf, %ecx
;;       movl    $1, %r8d
;;       movl    $3, %r9d
;;       callq   0x8a7
;;       movq    8(%rsp), %r14
;;       movq    %r14, %rdi
;;       movl    $3, %esi
;;       callq   0x905
;;       movq    8(%rsp), %r14
;;       movq    %r14, %rdi
;;       movl    $0, %esi
;;       movl    $0, %edx
;;       movl    $0x14, %ecx
;;       movl    $0xf, %r8d
;;       movl    $5, %r9d
;;       callq   0x943
;;       movq    8(%rsp), %r14
;;       movq    %r14, %rdi
;;       movl    $0, %esi
;;       movl    $0, %edx
;;       movl    $0x15, %ecx
;;       movl    $0x1d, %r8d
;;       movl    $1, %r9d
;;       callq   0x943
;;       movq    8(%rsp), %r14
;;       movq    %r14, %rdi
;;       movl    $0, %esi
;;       movl    $0, %edx
;;       movl    $0x18, %ecx
;;       movl    $0xa, %r8d
;;       movl    $1, %r9d
;;       callq   0x943
;;       movq    8(%rsp), %r14
;;       movq    %r14, %rdi
;;       movl    $0, %esi
;;       movl    $0, %edx
;;       movl    $0xd, %ecx
;;       movl    $0xb, %r8d
;;       movl    $4, %r9d
;;       callq   0x943
;;       movq    8(%rsp), %r14
;;       movq    %r14, %rdi
;;       movl    $0, %esi
;;       movl    $0, %edx
;;       movl    $0x13, %ecx
;;       movl    $0x14, %r8d
;;       movl    $5, %r9d
;;       callq   0x943
;;       movq    8(%rsp), %r14
;;       addq    $0x10, %rsp
;;       popq    %rbp
;;       retq
;;  2b4: ud2
;;
;; wasm[0]::function[11]:
;;       pushq   %rbp
;;       movq    %rsp, %rbp
;;       movq    8(%rdi), %r11
;;       movq    0x10(%r11), %r11
;;       addq    $0x30, %r11
;;       cmpq    %rsp, %r11
;;       ja      0x3c5
;;  2dc: movq    %rdi, %r14
;;       subq    $0x20, %rsp
;;       movq    %rdi, 0x18(%rsp)
;;       movq    %rsi, 0x10(%rsp)
;;       movl    %edx, 0xc(%rsp)
;;       movl    0xc(%rsp), %r11d
;;       subq    $4, %rsp
;;       movl    %r11d, (%rsp)
;;       movl    (%rsp), %ecx
;;       addq    $4, %rsp
;;       movq    %r14, %rdx
;;       movq    0xb0(%rdx), %rbx
;;       cmpq    %rbx, %rcx
;;       jae     0x3c7
;;  321: movq    %rcx, %r11
;;       imulq   $8, %r11, %r11
;;       movq    0xa8(%rdx), %rdx
;;       movq    %rdx, %rsi
;;       addq    %r11, %rdx
;;       cmpl    %ebx, %ecx
;;       cmovaeq %rsi, %rdx
;;       movq    (%rdx), %rax
;;       testq   %rax, %rax
;;       jne     0x384
;;  34a: subq    $4, %rsp
;;       movl    %ecx, (%rsp)
;;       subq    $0xc, %rsp
;;       movq    %r14, %rdi
;;       movl    $0, %esi
;;       movl    0xc(%rsp), %edx
;;       callq   0x9a1
;;       addq    $0xc, %rsp
;;       addq    $4, %rsp
;;       movq    0x18(%rsp), %r14
;;       jmp     0x38a
;;  384: andq    $0xfffffffffffffffe, %rax
;;       testq   %rax, %rax
;;       je      0x3c9
;;  393: movq    0x28(%r14), %r11
;;       movl    (%r11), %ecx
;;       movl    0x10(%rax), %edx
;;       cmpl    %edx, %ecx
;;       jne     0x3cb
;;  3a5: pushq   %rax
;;       popq    %rcx
;;       movq    0x18(%rcx), %rbx
;;       movq    8(%rcx), %rdx
;;       movq    %rbx, %rdi
;;       movq    %r14, %rsi
;;       callq   *%rdx
;;       movq    0x18(%rsp), %r14
;;       addq    $0x20, %rsp
;;       popq    %rbp
;;       retq
;;  3c5: ud2
;;  3c7: ud2
;;  3c9: ud2
;;  3cb: ud2
