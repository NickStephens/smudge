#include <stdio.h>
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#include <getopt.h>
#include "smudge.h"

unsigned suspicious = 0;
unsigned count = 0;

/* string searching */
wchar_t *wideStringBason = NULL;
DWORD wideStringBasonSz = 0;
char *stringBason = NULL;
DWORD stringBasonSz = 0;

/* options */
int verbose;
int excludeDisk = 0;
int excludeMemory = 0;
int disableDomainSearch = 0;
int disableURLSearch = 0;
int disableIPSearch = 0;
int enableAllTLDs = 0;
int processArchival = 0;
int aggressive = 0;
char baseDir[MAX_PATH] = {0};
char outFile[MAX_PATH] = {0};

void banner(void)
{

	printf("\t.:SMUDGE:.\n"); 
	printf("\t- discover hardcoded internet resources on disk and in memory\n");
	printf("\n");
}

int connectBackSearchFile(LPCTSTR filename)
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

int searchPath(LPCTSTR start)
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
			searchPath(newpath);
		} while (FindNextFile(hFind, &fdFile));
	}
	else
		count++;
		if (connectBackSearchFile(start) == 0)
			suspicious++;

	return 1;
}

void searchDisk()
{
	printf("[+] starting disk search starting from %s\n", baseDir);
	searchPath(baseDir);
}


void initialize()
{
	stringBasonSz = 0x100;
	stringBason = malloc(stringBasonSz);
	memset(stringBason, 0, stringBasonSz);

	wideStringBasonSz = 0x100;
	wideStringBason = malloc(wideStringBasonSz);
	memset(wideStringBason, 0, wideStringBasonSz);

	memset(outFile, 0, sizeof(outFile));
}

void cleanup()
{
	free(stringBason);
	free(wideStringBason);

	printf("[+] smudge completed scan\n");
}

void usage()
{
	printf("\t-xd\texclude disk searching\n");
	printf("\t-xm\texclude memory searching\n");
	printf("\t-a\taggressive scanning, search more than the first page of memory for every region in each process, this often isn't necessary\n");
	printf("\t-dd\tdisable domain seach\n");
	printf("\t-du\tdisable url seach\n");
	printf("\t-di\tdisable ip seach\n");
	printf("\t-tld\tenable searching of uncommon TLDs\n");
	printf("\t-dir <dir>\tperform disk search starting from <dir>\n");
	printf("\t-v\tbe verbose\n");
	printf("\t-o <file>\tlog results to <file>\n");
	printf("\t-h\tshow this help\n");
}

int main(int argc, char **argv)
{
	int ac;

	banner();
	initialize();

	for(ac=1;ac<argc;ac++)
	{
		if (!strcmp(argv[ac], "-xd"))
			excludeDisk = 1;
		if (!strcmp(argv[ac], "-xm"))
			excludeMemory = 1;
		if (!strcmp(argv[ac], "-v"))
			verbose = 1;
		if (!strcmp(argv[ac], "-dd"))
			disableDomainSearch = 1;
		if (!strcmp(argv[ac], "-du"))
			disableURLSearch = 1;
		if (!strcmp(argv[ac], "-di"))
			disableIPSearch = 1;
		if (!strcmp(argv[ac], "-tld"))
			enableAllTLDs = 1;
		if (!strcmp(argv[ac], "-a"))
			aggressive = 1;
		if (!strcmp(argv[ac], "-pa"))
			processArchival = 1;
		if (!strcmp(argv[ac], "-h"))
		{
			usage();
			ExitProcess(0);
		}
		if (!strcmp(argv[ac], "-o"))
			if ((++ac) < argc)
				strncpy(outFile, argv[ac], sizeof(outFile));
		if (!strcmp(argv[ac], "-dir"))
			if ((++ac) < argc)
				strncpy(baseDir, argv[ac], sizeof(baseDir));
	}	

	if (!excludeDisk)
		searchDisk();
	if (!excludeMemory)
		searchMemory();

	cleanup();
}	
