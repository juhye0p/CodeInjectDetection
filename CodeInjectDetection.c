#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <stdbool.h>
#include <wchar.h>
#include "ntdll.h"

typedef NTSTATUS(NTAPI * PFNtQueryInformationThread)(
	HANDLE          ThreadHandle,
	THREADINFOCLASS ThreadInformationClass,
	PVOID           ThreadInformation,
	ULONG           ThreadInformationLength,
	PULONG          ReturnLength
);

HANDLE ntHandle = NULL;
PFNtQueryInformationThread pNtQueryInformationThread = NULL;

bool findProcessName(DWORD ownPID, WCHAR* szlExecFile) {
	HANDLE SnapShot = NULL;
	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32W);

	if ((SnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == NULL) {
		return false;
	}
	
	if (!Process32FirstW(SnapShot, &pe32)) {
		return false;
	}

	do {
		if (pe32.th32ProcessID == ownPID) {
			wcscpy_s(szlExecFile, 256 * 2, pe32.szExeFile);
			CloseHandle(SnapShot);
			return true;
		}
	} while (Process32NextW(SnapShot, &pe32));
	return false;
}

DWORD scanThread(LPTHREADENTRY32 te32) {
	HANDLE th = NULL;
	HANDLE thOwn = NULL;
	PVOID thStartAddress = NULL;
	MEMORY_BASIC_INFORMATION mbi_structure = { 0, };
	WCHAR szlExecFile[256 * 2];
	
	if ((th = OpenThread(THREAD_ALL_ACCESS, false, te32->th32ThreadID)) == NULL) {
		return 0xffffffff;
	}
	printf("[.] scanning thread (%d)\n", te32->th32ThreadID);
	
	NTSTATUS status = pNtQueryInformationThread(th, ThreadQuerySetWin32StartAddress, &thStartAddress, sizeof(PVOID), NULL);
	CloseHandle(th);

	if (!NT_SUCCESS(status)) {
		return 0xffffffff;
	}

	if ((thOwn = OpenProcess(THREAD_ALL_ACCESS, false, te32->th32OwnerProcessID)) == NULL) {
		return 0xfffffff;
	}
	if ((VirtualQueryEx(thOwn, thStartAddress, &mbi_structure, sizeof(MEMORY_BASIC_INFORMATION))) == 0) {
		return 0xfffffff;
	}

	//memory mapped into hard drive
	if (mbi_structure.State == MEM_COMMIT) {
		//if it is not equal to MEM_IMAGE, it is the code that is not backed by current executable file
		if (mbi_structure.Type != MEM_IMAGE) {
			if (!findProcessName(te32->th32OwnerProcessID, szlExecFile)) {
				puts("[-] cannot found owner process name");
			}
			else {
				wprintf(L"[*] process name : %ls\n", szlExecFile);
			}
			printf("[*] pid : %d\n", te32->th32OwnerProcessID);
			printf("[*] thread start address : %x\n", thStartAddress);
		}
	}

	return 0x00000000;
}

DWORD findThreads() {
	HANDLE SnapShot = NULL;
	THREADENTRY32 te32;
	te32.dwSize = sizeof(THREADENTRY32);

	if ((SnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)) == NULL) {
		return 0xffffffff;
	}

	if (!Thread32First(SnapShot, &te32)) {
		return 0xffffffff;
	}

	do {
		if (scanThread(&te32) == 0xffffffff) {
			printf("[-] did not scan correctly..(%d)\n", te32.th32ThreadID);
		}
	} while (Thread32Next(SnapShot, &te32));
	CloseHandle(SnapShot);

	return 0x00000000;
}

int main(int argc, char* argv[]) {
	DWORD res = 0x00000000;

	if ((ntHandle = GetModuleHandleA((LPCSTR)"ntdll.dll")) == NULL) {
		puts("[!] failed to get ntdll handle..");
		exit(-1);
	}
	if ((pNtQueryInformationThread = GetProcAddress(ntHandle, (LPCSTR)"NtQueryInformationThread")) == NULL) {
		puts("[!] failed to get NtQueryInformationThread's address");
		CloseHandle(ntHandle);
		exit(-1);
	}

	res = findThreads();

	if (res == 0xffffffff) {
		puts("[-] did not work correctly..");
	}
	else {
		puts("[+] done");
	}

	return 0;
}