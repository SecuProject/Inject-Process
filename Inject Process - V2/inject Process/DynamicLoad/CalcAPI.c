#include <Windows.h>
#include <winternl.h>
#include <intrin.h>
#include <stdio.h>

// https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format



// Check if compile in 32/64 bit 
#ifdef _M_IX86 
	#define IS_COMP_X32 TRUE
#elif defined(_M_AMD64)
	#define IS_COMP_X32 FALSE
#endif


// fnv1a 32 bit hash algorithm
DWORD __forceinline compute_hash(const void *inputStr, UINT32 len) {
	const unsigned char *data = (const unsigned char *)inputStr;
	DWORD hash = 2166136261;
	char current = *data;

	while ((len != 0 && *data != 0) || (UINT32)(data - (const unsigned char *)inputStr) < len) {
		if (*data != 0) {
			// custom toupper
			if (current >= 'a')
				current -= 0x20;

			hash ^= current;
			hash *= 16777619;

		}
		++data;
		current = *data;
	}
	return hash;
}



// Process Environment Block 
PPEB get_peb(){
#if IS_COMP_X32
	return (PPEB)__readfsdword(0x30);
#else
	return (PPEB)__readgsqword(0x60);
#endif
}


/*
typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD   VirtualAddress;
	DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
*/
PIMAGE_DATA_DIRECTORY get_data_dir(LPBYTE lpBaseAddress, WORD wIndex){
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(lpBaseAddress + pDosHeader->e_lfanew);
	return &pNtHeaders->OptionalHeader.DataDirectory[wIndex];
}



/*
typedef struct _LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
	PVOID Reserved3[2];
	UNICODE_STRING FullDllName;
	BYTE Reserved4[8];
	PVOID Reserved5[3];
	union {
		ULONG CheckSum;
		PVOID Reserved6;
	} DUMMYUNIONNAME;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
*/
LPBYTE find_module(DWORD dwModuleHash){
	PPEB pPeb = get_peb();
	LIST_ENTRY *pListEntry = pPeb->Ldr->InMemoryOrderModuleList.Flink;
	if (*(char*)(pPeb + 0x2)) {
		printf("\t[X] Debugger Detected !!!\n");
		// ExitProcess
		// return 0;
	}
	do	{
		LDR_DATA_TABLE_ENTRY *pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pListEntry;
		UNICODE_STRING dllName = pLdrDataTableEntry->FullDllName;


		// check if found dwModuleHash 
		if (dllName.Length != 0 && compute_hash(dllName.Buffer, dllName.Length) == dwModuleHash)
			return (LPBYTE)pLdrDataTableEntry->Reserved2[0];

		pListEntry = pListEntry->Flink;

	} while (pListEntry != pPeb->Ldr->InMemoryOrderModuleList.Flink);

	return 0;
}



/*
typedef struct _IMAGE_EXPORT_DIRECTORY {
	DWORD   Characteristics;
	DWORD   TimeDateStamp;
	WORD    MajorVersion;
	WORD    MinorVersion;
	DWORD   Name;
	DWORD   Base;
	DWORD   NumberOfFunctions;
	DWORD   NumberOfNames;
	DWORD   AddressOfFunctions;     // RVA from base of image
	DWORD   AddressOfNames;         // RVA from base of image
	DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
*/

FARPROC find_api(DWORD dwModuleHash, DWORD dwProcHash){
	LPBYTE lpBaseAddress = find_module(dwModuleHash);
	PIMAGE_DATA_DIRECTORY pDataDir = get_data_dir(lpBaseAddress, IMAGE_DIRECTORY_ENTRY_EXPORT);
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(lpBaseAddress + pDataDir->VirtualAddress);
	LPDWORD pNames = (LPDWORD)(lpBaseAddress + pExportDir->AddressOfNames);
	LPWORD pOrdinals = (LPWORD)(lpBaseAddress + pExportDir->AddressOfNameOrdinals);



	// search the function in the image export directory
	for (SIZE_T i = 0; i < pExportDir->NumberOfNames; ++i){
		char *szName = (char *)lpBaseAddress + (DWORD_PTR)pNames[i];

		// check if found szName 
		if (compute_hash(szName, 0) == dwProcHash)
			// return the address of the function
			return (FARPROC)(lpBaseAddress + ((DWORD *)(lpBaseAddress + pExportDir->AddressOfFunctions))[pOrdinals[i]]);
	}

	return NULL;
}
