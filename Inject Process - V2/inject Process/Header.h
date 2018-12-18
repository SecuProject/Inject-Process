#include <Windows.h>
#include <winternl.h>
#include <intrin.h>
#include <stdio.h>

// this is a variation of the fnv1a_32 hash algorithm, but keeping the original primes,
// changed to allow both unicode and char*, slower but same distribution for ascii text
DWORD __forceinline compute_hash(const void *input, UINT32 len) {
	const unsigned char *data = (const unsigned char *)input;
	DWORD hash = 2166136261;

	while (1) {
		char current = *data;
		if (len == 0) {
			if (*data == 0)
				break;
		}
		else {
			if ((UINT32)(data - (const unsigned char *)input) >= len)
				break;
			if (*data == 0) {
				++data;
				continue;
			}
		}

		// toupper
		if (current >= 'a')
			current -= 0x20;
		hash ^= current;
		hash *= 16777619;

		++data;
	}
	return hash;
}

PPEB get_peb() {
#ifdef _M_IX86 
	return (PPEB)__readfsdword(0x30);
#elif defined(_M_AMD64)
	return (PPEB)__readgsqword(0x60);
#endif
}

PIMAGE_DATA_DIRECTORY get_data_dir(LPBYTE lpBaseAddress, WORD wIndex) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(lpBaseAddress + pDosHeader->e_lfanew);
	return &pNtHeaders->OptionalHeader.DataDirectory[wIndex];
}

LPBYTE find_module(DWORD dwModuleHash) {
	PPEB pPeb = get_peb();
	LIST_ENTRY *pListEntry = pPeb->Ldr->InMemoryOrderModuleList.Flink;
	if (*(char*)(pPeb + 0x2)) {
		printf("\t[X] Debugger Detected !!!\n");
		// ExitProcess
		// return 0;
	}
	do {
		LDR_DATA_TABLE_ENTRY *pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pListEntry;

		UNICODE_STRING dllName = pLdrDataTableEntry->FullDllName;

		if (dllName.Length != 0 && compute_hash(dllName.Buffer, dllName.Length) == dwModuleHash)
			return (LPBYTE)pLdrDataTableEntry->Reserved2[0];

		pListEntry = pListEntry->Flink;

	} while (pListEntry != pPeb->Ldr->InMemoryOrderModuleList.Flink);

	return 0;
}

FARPROC find_api(DWORD dwModuleHash, DWORD dwProcHash) {
	LPBYTE lpBaseAddress = find_module(dwModuleHash);
	PIMAGE_DATA_DIRECTORY pDataDir = get_data_dir(lpBaseAddress, IMAGE_DIRECTORY_ENTRY_EXPORT);
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(lpBaseAddress + pDataDir->VirtualAddress);
	LPDWORD pNames = (LPDWORD)(lpBaseAddress + pExportDir->AddressOfNames);
	LPWORD pOrdinals = (LPWORD)(lpBaseAddress + pExportDir->AddressOfNameOrdinals);

	for (SIZE_T i = 0; i < pExportDir->NumberOfNames; ++i) {
		char *szName = (char *)lpBaseAddress + (DWORD_PTR)pNames[i];
		if (compute_hash(szName, 0) == dwProcHash)
			return (FARPROC)(lpBaseAddress + ((DWORD *)(lpBaseAddress + pExportDir->AddressOfFunctions))[pOrdinals[i]]);
	}

	return NULL;
}




DWORD __forceinline compute_hash(const void *input, UINT32 len);
