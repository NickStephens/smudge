#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <wchar.h>
#include <psapi.h>
#include "smudge.h"

#define MEM_INCREMENT 0x1000

DWORD basonidx = 0;
DWORD wideBasonIdx = 0;
int warned = 0;
int image_warned = 0;

DWORD currentProcId = 0;

unsigned int procOccurences;

void printProcessInfo(HANDLE hProc)
{
	TCHAR procName[MAX_PATH] = {0};
	HMODULE hMod;	
	DWORD cbNeeded;

	if (hProc != NULL)
	{
		if (EnumProcessModules(hProc, &hMod, sizeof(hMod), &cbNeeded))
		{
			GetModuleBaseName(hProc, hMod, procName, 
				sizeof(procName)/sizeof(TCHAR));
		}
		else {
			if (!image_warned)
			{
				printf("failed to read image name of [%d]\n", currentProcId);
				printf("this is likely because smudge was compiled as a 32bit executable, you'll need a 64bit executable to query this processes's name.\n");
				image_warned++;
			}
		}
	}

	printf("[!] Process %d (%s)\n", currentProcId, procName);
}

/* POC Wide String scanning. I know this is inefficient. */
int scanMemoryWide(HANDLE hProc, void *memory, size_t sz)
{
	size_t cnt;
	wchar_t cimd;
	char *temp;

	wchar_t *s = memory;
	memset(wideStringBason, 0, wideStringBasonSz);
	for(cnt=0;cnt<(sz/2);cnt++) 
	{
		cimd = s[cnt];
		if ((cimd >= 0x21) && (cimd <= 0x7e))
		{
			wideStringBason[wideBasonIdx++] = cimd;
		}
		else
		{
			wideStringBason[wideBasonIdx] = 0;
			if (wideBasonIdx > 0)
			{
				temp = convertToAnsi(wideStringBason);
				if (temp == NULL)
					return 0;

				if (isResource(temp))
				{
					if (!procOccurences)
						printProcessInfo(hProc);
					wprintf(L"  %ls\n", wideStringBason);
					procOccurences++;
				}
				free(temp);
			}
			memset(wideStringBason, 0, wideBasonIdx);
			wideBasonIdx= 0;
		}
		if ((wideBasonIdx*sizeof(wchar_t)) == wideStringBasonSz)
		{
			wideStringBasonSz *= 2;
			wideStringBason = realloc(wideStringBason, wideStringBasonSz);
			if (wideStringBason == NULL)
			{
				print_error("[-] realloc");
				ExitProcess(1);
			}
		}
	}
	return 0;
}

int scanMemory(HANDLE hProc, void *memory, size_t sz)
{
	size_t cnt;
	char cimd;
	char *temp;

	char *s = memory;
	memset(stringBason, 0, stringBasonSz);
	for(cnt=0;cnt<sz;cnt++) 
	{
		cimd = s[cnt];
		if ((cimd >= 0x21) && (cimd <= 0x7e))
		{
			stringBason[basonidx++] = cimd;
		}
		else
		{
			stringBason[basonidx] = 0;
			if (basonidx > 0)
			{
				temp = malloc(basonidx+1);
				if (temp == NULL)
				{
					print_error("malloc");
					return 1;
				}
				strncpy(temp, stringBason, basonidx+1);
				if (isResource(temp))
				{
					if (!procOccurences)
						printProcessInfo(hProc);
					printf("  %s\n", stringBason);
					procOccurences++;
				}
				free(temp);
			}
			memset(stringBason, 0, basonidx);
			basonidx = 0;
		}
		if (basonidx == stringBasonSz)
		{
			stringBasonSz *= 2;
			stringBason = realloc(stringBason, stringBasonSz);
			if (stringBason == NULL)
			{
				print_error("[-] realloc");
				ExitProcess(1);
			}
		}
	}
	return 0;
}

int prepareAndScan(HANDLE hProc, void *baseAddr, size_t sz)
{
	void *dest;
	int result = 0;
	SIZE_T nRead;

	dest = VirtualAlloc(NULL, sz, MEM_COMMIT, PAGE_READWRITE);
	if (dest == NULL)
	{
		print_error("[-] VirtualAlloc");
		return 0;
	}

	if (!ReadProcessMemory(hProc, baseAddr, dest, sz, &nRead))
	{
		// somehow we got a bad page, just skip it

		// and we're no longer contiguous
		wideBasonIdx = 0;
		basonidx = 0;
		return 0;
	}
	if (nRead != MEM_INCREMENT)
	{
		printf("[-] read less bytes than attempted %d\n", nRead);
	}

	result = scanMemory(hProc, dest, nRead);
	result |= scanMemoryWide(hProc, dest, nRead);

	VirtualFree(dest, 0, MEM_RELEASE);

	return result;
}

int searchRegion(HANDLE hProc, void *baseAddr, size_t sz)
{
	unsigned i;
	int result = 0;

	if (aggressive)
	{
		for(i=0;i<(sz/MEM_INCREMENT);i++)
		{
			result |= prepareAndScan(hProc, baseAddr+(i*MEM_INCREMENT), MEM_INCREMENT);	
		}
	}	
	else
	{
		result = prepareAndScan(hProc, baseAddr, MEM_INCREMENT);
	}

	return result;
}

void searchProc(HANDLE hProc)
{
	SYSTEM_INFO si;
	uintptr_t lpMem;
	MEMORY_BASIC_INFORMATION mbi;
	SIZE_T mibSz;

	/* zero procOccurences to make alerts possible */
	procOccurences = 0;

	GetSystemInfo(&si);
	lpMem = 0;

	while(((void *)lpMem) < si.lpMaximumApplicationAddress)
	{
		mibSz = VirtualQueryEx(hProc, (void *)lpMem, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
		if (mibSz != sizeof(MEMORY_BASIC_INFORMATION))
		{
			/* this will only fail if we're scanning a 32bit process while smudge is running in 64bit mode */
			/* if it fails return, because we hit the end of the 32bit process's addresses space */
			return;
		}
		else
		{
			if (mbi.State == MEM_COMMIT)
			{
				searchRegion(hProc, mbi.BaseAddress, mbi.RegionSize);
			}
			lpMem = (uintptr_t)(mbi.BaseAddress + mbi.RegionSize);
		}
	}

}

void analyzeProcess(DWORD processId)
{
	HANDLE hProc;

	hProc = OpenProcess(PROCESS_QUERY_INFORMATION|
				   PROCESS_VM_READ,
				   FALSE, processId);	

	if (hProc == NULL)
	{
		if (warned == 0)
		{
			printf("[-] failed to open some processes, elevate to Administrator\n", processId);
			warned++;
		}
	}
	else
		searchProc(hProc);

	CloseHandle(hProc);
}

/* get debug priviledges so we can examine all processes */
int getDebugPrivs(void)
{
	TOKEN_PRIVILEGES tp;
	TOKEN_PRIVILEGES op;
	HANDLE hToken;
	LUID luid;
	DWORD sz;	

	SetLastError(0);

	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
		print_error("OpenProcessToken");

	if(!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
		print_error("LookupPrivilegeValue");
	
	memset(&tp, 0, sizeof(tp));
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, 0, (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
		print_error("AdjustTokenPrivileges");
}

int searchMemory(void)
{
	DWORD aProcesses[1024], cbNeeded, cProcesses;
	unsigned i;

	getDebugPrivs();

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		printf("[-] failed to enumProcesses\n");
		return 1;	
	}

	cProcesses = cbNeeded / sizeof(DWORD);

	for (i=0;i<cProcesses;i++)
	{
		if ((aProcesses[i] != 0) && (aProcesses[i] != GetCurrentProcessId()))
		{
			currentProcId = aProcesses[i];
			analyzeProcess(aProcesses[i]);	
		}
	}

	return 0;
}
