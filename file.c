#include <windows.h>
#include <stdio.h>
#include "smudge.h"

int searchFile(LPCTSTR filename)
{
	HANDLE s;
	DWORD sz;
	DWORD bytepos;
	DWORD basonptr;
	DWORD basonidx;
	unsigned occurences = 0;
	char *temp;
	char cimd;
	wchar_t cwimd;
	DWORD out;
	OVERLAPPED ovp;
	LONG outl;

	s = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (s == INVALID_HANDLE_VALUE)
	{
		if (verbose)
			printf("[-] failed to open %s for inspection\n", filename);
		return 0;
	}

	sz = GetFileSize(s, NULL);
	
	basonidx = 0;
	/* plain string search */
	for(bytepos=0;bytepos < sz;bytepos++)
	{
		/* POC has slow i/o... */
		/* TODO file mapping */
		memset(&ovp, 0, sizeof(ovp));
		if (!ReadFile(s, &cimd, 1, &out, NULL))
		{
			print_error("ReadFile");
		}
		if (cimd >= 0x21 && cimd <= 0x7e)
		{
			stringBason[basonidx++] = cimd;
		}
		else // end of string
		{
			stringBason[basonidx] = 0;
			if (basonidx > 0)
			{
				// is it a url or a IP address?
				temp = malloc(basonidx+1);
				if (temp == NULL)
				{
					print_error("malloc");
					ExitProcess(1);
				}
				strncpy(temp, stringBason, basonidx+1);
				if(isResource(temp))
				{
					if (occurences == 0)
						printf("[!] found something in file \"%s\"\n", filename);
					printf("%s\n", stringBason);
					occurences++;
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
				print_error("realloc");
				printf("[-] out of memory, exiting\n");
				ExitProcess(1);
			}
		}
	}
	return 1;
}

int findFiles(LPCTSTR start)
{
	DWORD attr;
	char path[MAX_PATH] = {0};
	char newpath[MAX_PATH] = {0};
	WIN32_FIND_DATA fdFile;
	HANDLE hFind;

	attr = GetFileAttributes(start);	


	if (attr == INVALID_FILE_ATTRIBUTES)
	{
		print_error("[-] GetFileAttributes");
		return 0;
	}
	// avoid softlinks
	if ((attr & FILE_ATTRIBUTE_REPARSE_POINT) && !(attr & FILE_ATTRIBUTE_DIRECTORY))
	{
		return 0;
	}
	if (attr & FILE_ATTRIBUTE_DIRECTORY)
	{
		//printf("[!] (%s) is a directory\n", start);

		snprintf(path, sizeof(path), "%s\\*", start);
		hFind = FindFirstFile(path, &fdFile);
		if (hFind == INVALID_HANDLE_VALUE)
		{
			printf("[-] Path not found: %s\n", start);
			return 0;
		}
		do 
		{		
			if ((strcmp(fdFile.cFileName, ".") == 0) || (strcmp(fdFile.cFileName, "..") == 0))
				continue;
			snprintf(newpath, sizeof(newpath), "%s\\%s", start, fdFile.cFileName);
			searchFile(newpath);
		} while (FindNextFile(hFind, &fdFile));
	}
	else
		searchFile(start);

	return 1;
}

int searchDisk()
{
	printf("[+] starting disk search starting from %s\n", baseDir);
	return findFiles(baseDir);
}
