#include <windows.h>
#include <string>
#include <stdio.h>
#include <iostream>
#include <tchar.h>

#define N_ELEMENTS(x) sizeof(x)/sizeof(x[0])

//----------------------------------------------------------------------------------------------------------------------
typedef enum _SYSTEM_INFORMATION_CLASS
{
        SystemFileCacheInformation = 21,
        SystemMemoryListInformation = 80
};

//----------------------------------------------------------------------------------------------------------------------
typedef enum _SYSTEM_MEMORY_LIST_COMMAND
{
	MemoryCaptureAccessedBits,
	MemoryCaptureAndResetAccessedBits,
	MemoryEmptyWorkingSets,
	MemoryFlushModifiedList,
	MemoryPurgeStandbyList,
	MemoryPurgeLowPriorityStandbyList,
	MemoryCommandMax
} SYSTEM_MEMORY_LIST_COMMAND;

//----------------------------------------------------------------------------------------------------------------------
typedef struct _SYSTEM_FILECACHE_INFORMATION
{
	SIZE_T CurrentSize;
	SIZE_T PeakSize;
	ULONG PageFaultCount;
	SIZE_T MinimumWorkingSet;
	SIZE_T MaximumWorkingSet;
	SIZE_T CurrentSizeIncludingTransitionInPages;
	SIZE_T PeakSizeIncludingTransitionInPages;
	ULONG TransitionRePurposeCount;
	ULONG Flags;
} SYSTEM_FILECACHE_INFORMATION;


//----------------------------------------------------------------------------------------------------------------------
void DisplayError(DWORD Err)
{
	LPVOID lpMessageBuffer;
	HMODULE Hand = LoadLibrary(L"NTDLL.DLL");

	FormatMessage( 
		FORMAT_MESSAGE_ALLOCATE_BUFFER | 
		FORMAT_MESSAGE_FROM_SYSTEM | 
		FORMAT_MESSAGE_FROM_HMODULE,
		Hand, 
		Err,  
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR) &lpMessageBuffer,  
		0,  
		NULL );

	// Now display the string.
	printf("%ls\n", lpMessageBuffer);

	// Free the buffer allocated by the system.
	LocalFree( lpMessageBuffer ); 
	FreeLibrary(Hand);
}


//----------------------------------------------------------------------------------------------------------------------
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
		return FALSE;

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : 0;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
		return FALSE;

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		return FALSE;

	return TRUE;
}


//----------------------------------------------------------------------------------------------------------------------
static void PrintLastError(DWORD errCode)
{
	wchar_t err[2048];
	memset(err, 0, 2048);

	if (!FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
		NULL, errCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // default language
		err, 2048, NULL))
		return;

	std::wcout << ", Warning: " << err << std::endl;
}


//----------------------------------------------------------------------------------------------------------------------
static void purgeDiskCaches()
{
	DWORD dwSize = MAX_PATH;
	WCHAR szLogicalDrives[MAX_PATH] = { 0 };
	DWORD dwResult = GetLogicalDriveStrings(dwSize, szLogicalDrives);

	if (dwResult > 0 && dwResult <= MAX_PATH)
	{
		WCHAR* szSingleDrive = szLogicalDrives;
		while (*szSingleDrive)
		{
			UINT driveType = GetDriveType(szSingleDrive);
			if (driveType == DRIVE_FIXED)
			{
				LPCTSTR DOS_PREFIX = L"\\\\.\\";
				WCHAR path[32] = {};
				_tcscat(path, DOS_PREFIX);
				_tcscat(path, szSingleDrive);
				std::wcout << "Flushing caches for disk: " << szSingleDrive << std::endl;
				HANDLE hDevice = CreateFile(path, FILE_READ_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
				if (hDevice != INVALID_HANDLE_VALUE)
				{
					::CloseHandle(hDevice);
				}
				else
				{
					//	<Sarang.Baheti>	29-Dec-2016
					//	it's okay even if we have errors, caches are invalidated
					//
#ifdef _DEBUG
					DWORD le = GetLastError();
					if (le == ERROR_SHARING_VIOLATION)
					{
						std::wcout << L", Warning: Sharing Violation" << std::endl;
					}
					else if (le != ERROR_ACCESS_DENIED)
					{
						std::wcout << L", Warning: Access Denied" << std::endl;
					}
					else
					{
						PrintLastError(le);
					}
#endif
				}
			}
			// get the next drive
			szSingleDrive += wcslen(szSingleDrive) + 1;
		}
	}
}

//----------------------------------------------------------------------------------------------------------------------
static void printInfo()
{
	std::wcout << std::endl;
	std::wcout << L"A handy utility to purge all caches on system" << std::endl;
	std::wcout << L"Author: Sarang.Baheti, extended disk-flush utility created by <vitillo>" << std::endl;
	std::wcout << L"source repository: https://www.github.com/sarangbaheti/flush" << std::endl;
	std::wcout << std::endl;
	std::wcout << L"It clears following caches on Windows systems:" << std::endl;
	std::wcout << L"\t- Disk Caches, does not accounts for SSD/NVMe yet" << std::endl;
	std::wcout << L"\t- Various Ram Memory caches (see Rammap tool for details)" << std::endl << std::endl;
	
	std::wcout << std::endl;
}

//----------------------------------------------------------------------------------------------------------------------
int main(int argc, char* argv[])
{
	printInfo();

	HMODULE ntdll = LoadLibrary(L"ntdll.dll");
	if (!ntdll)
	{
		fprintf(stderr, "Can't load ntdll.dll\n");
		return -1;
	}

	NTSTATUS (WINAPI *NtSetSystemInformation)(INT, PVOID, ULONG) = (NTSTATUS (WINAPI *)(INT, PVOID, ULONG))GetProcAddress(ntdll, "NtSetSystemInformation");
	if (!NtSetSystemInformation)
	{
		fprintf(stderr, "Can't get NtSetSystemInformation address\n");
		return -1;
	}

	HANDLE processToken;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &processToken) == FALSE)
		return 3;         

	if (SetPrivilege(processToken, L"SeIncreaseQuotaPrivilege", TRUE))
	{
		SYSTEM_FILECACHE_INFORMATION info;
		ZeroMemory(&info, sizeof(info));
		info.MinimumWorkingSet = -1;
		info.MaximumWorkingSet = -1;
		NTSTATUS ret = NtSetSystemInformation(SystemFileCacheInformation, &info, sizeof(info));
		if (ret >= 0)
		{
			printf("Flush FileCache WorkingSet : ok\n");
		}else
		{
			DisplayError(ret);
			return -1;
		}
	} 
	else 
	{
		printf("Failure to set required privileges\n");
		return -1;
	}

	if (SetPrivilege(processToken, L"SeProfileSingleProcessPrivilege", TRUE))
	{
		SYSTEM_MEMORY_LIST_COMMAND commands[] = { MemoryEmptyWorkingSets, MemoryFlushModifiedList, MemoryPurgeStandbyList, MemoryPurgeLowPriorityStandbyList};
		const char* msgs[] = {"Empty working sets", "Flushing Modified Lists", "Purging Memory Standby Lists", "Purging LowPriority Standby Lists"};
		for (int idx = 0; idx < N_ELEMENTS(commands); ++idx)
		{
			SYSTEM_MEMORY_LIST_COMMAND command = commands[idx];
			NTSTATUS ret = NtSetSystemInformation(SystemMemoryListInformation, &command, sizeof(command));
			if (ret >= 0)
			{
				printf("%s : ok\n", msgs[idx]);
			}
			else
			{
				DisplayError(ret);
				return -1;
			}
		}

		printf("\nPurging disk caches..\n");
		purgeDiskCaches();

	} 
	else 
	{
		printf("Failure to set required privileges\n");
		return -1;
	}

	std::wcout << std::endl;

	return 0;
}