#ifndef STRUCTS_H
#define STRUCTS_H

#include <Windows.h>
#include <winternl.h>
#include <intrin.h>

typedef struct _SYSCALL_TABLE_ENTRY {
	PVOID pFuncAddress; // The address of a syscall function
	PVOID pInstrAddress; // The address of the syscall *instruction* (for indirect syscalls)
	UINT32 Hash; // The hash value of the syscall name
	WORD SyscallSsn; // The SSN of the syscall
	struct _SYSCALL_TABLE_ENTRY* NextSyscall; //The next syscall in the list
} SYSCALL_TABLE_ENTRY, * PSYSCALL_TABLE_ENTRY;



typedef struct _SYSCALL_TABLE {
	PSYSCALL_TABLE_ENTRY TableHead; // Head of the linked list 
} SYSCALL_TABLE, * PSYSCALL_TABLE;



typedef struct _CALL_CONTEXT {
	DWORD ArgumentCount;   // How many arguments this specific syscall needs
	UINT64 Arguments[16];  // Array holding the arguments (cast to 8 bytes each)
} CALL_CONTEXT, * PCALL_CONTEXT;


#endif // STRUCTS_H
