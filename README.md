# Indirect Syscall Code Injection 

## **⚠️ DISCLAIMER: EDUCATIONAL PURPOSE ONLY ⚠️**
This repository is intended for educational purposes only. The techniques demonstrated here are meant to help security professionals understand and defend against malicious activities. Unauthorized use of these techniques on systems you do not own or have explicit permission to test is illegal and unethical. Always ensure you have proper authorization before conducting any security testing.

## Overview
This project focuses primarily on an advanced evasion technique known as **indirect syscall calling**.

Indirect syscall calling is a technique designed to evade EDRs that analyze processes and may hook critical API calls to detect malicious software. The technique works by bypassing the need for WinAPI or even NTAPI; instead, it executes the API calls directly, avoiding calls to external wrapper functions that might be subject to monitoring or inspection.

With this specific (indirect) technique, rather than simply executing the `syscall` instruction from our own assembly code, the program prepares the necessary parameters in the appropriate registers. 
It then jumps to the function's original address within `ntdll.dll` to execute only the `syscall` **instruction** itself. This prevents the detection of `syscall` executions originating from locations other than `ntdll.dll`.

## Architecture
The architecture of this technique resembles the implementation of **Hell's Gate**, utilizing two primary structures: `SYSCALL_TABLE` and `SYSCALL_TABLE_ENTRY`. 
`SYSCALL_TABLE` holds the head of a linked list of `SYSCALL_TABLE_ENTRY` structures, where each entry represents a **single syscall** containing the following data: 

- The starting **address of the function** within `ntdll`
- The **address of the `syscall` instruction** within the function
- The **hashed function name**
- The **syscall's SSN** (System Service Number) - essentially an ID that tells the kernel exactly which operation to perform

By parsing `ntdll` and its export table, we extract all this data and store it in the list.

The next part of the technique is the **dynamic syscall dispatcher** written in assembly. 
Briefly, since different functions require varying numbers and types of arguments, I defined a structure containing an array to hold these arguments; 
the assembly code then arranges them along with the values ​​from the `SYSCALL_TABLE_ENTRY` into the appropriate registers and onto the stack, in accordance with the **Windows calling convention.**

### Syscall calling convention (x64)

| Position | Register / location | Notes |
|----------|--------------------|-------|
| Arg 1    | R10                | NOT RCX - syscall ABI differs from Win64 ABI |
| Arg 2    | RDX                | |
| Arg 3    | R8                 | |
| Arg 4    | R9                 | |
| Arg 5+   | [RSP+0x28], [RSP+0x30], ... | 32 bytes shadow space below them |
| Return   | RAX                | NTSTATUS |
| SSN      | EAX                | set immediately before `syscall` |

The dispatcher must:
1. Copy the first four `CALL_CONTEXT.Arguments` into R10/RDX/R8/R9.
2. Push arguments 5..N onto the stack.
3. Load the SSN into EAX.
4. `call` the address of the `syscall` instruction inside ntdll.
5. Restore non-volatile registers and return the NTSTATUS in RAX.
