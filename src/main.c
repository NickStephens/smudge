#include <stdio.h>
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#include "smudge.h"

unsigned suspicious = 0;
unsigned count = 0;

/* string searching */
wchar_t *wideStringBason = NULL;
DWORD wideStringBasonSz = 0;
char *stringBason = NULL;
DWORD stringBasonSz = 0;

/* options */
int verbose = 0;
int excludeDisk = 0;
int excludeMemory = 0;
int disableDomainSearch = 0;
int disableURLSearch = 0;
int disableIPSearch = 0;
int enableAllTLDs = 0;
int processArchival = 0;
int aggressive = 0;
int showCommonNoise = 0;

void banner(void)
{

	printf(".:SMUDGE:.\n"); 
	printf("- discover hardcoded internet resources on disk and in memory\n");
	printf("\n");
}


void initialize()
{
	stringBasonSz = 0x100;
	stringBason = malloc(stringBasonSz);
	memset(stringBason, 0, stringBasonSz);

	wideStringBasonSz = 0x100;
	wideStringBason = malloc(wideStringBasonSz);
	memset(wideStringBason, 0, wideStringBasonSz);

	strncpy(baseDir, "C:\\WINDOWS\\", sizeof(baseDir));
}

void cleanup()
{
	free(stringBason);
	free(wideStringBason);

	printf("[+] smudge completed scan\n");
}

void usage()
{
	printf("\t-xd\t\texclude disk searching\n");
	printf("\t-xm\t\texclude memory searching\n");
	printf("\t-dd\t\tdisable domain seach\n");
	printf("\t-du\t\tdisable url seach\n");
	printf("\t-di\t\tdisable ip seach\n");
	printf("\t-a\t\taggressive scanning\n");
	printf("\t-sc\t\tshow common noise\n");
	printf("\t-tld\t\tenable searching of uncommon TLDs\n");
	printf("\t-dir <dir>\tperform disk search starting from <dir>, default C:\\WINDOWS\\\n");
	printf("\t-v\t\tbe verbose\n");
	printf("\t-h\t\tshow this help\n");
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
		if (!strcmp(argv[ac], "-sc"))
			showCommonNoise = 1;
		if (!strcmp(argv[ac], "-a")) // aggressive scanning, search more than the first page of memory for every region in each process, this often isn't necessary
			aggressive = 1;
		if (!strcmp(argv[ac], "-pa"))
			processArchival = 1;
		if (!strcmp(argv[ac], "-h"))
		{
			usage();
			ExitProcess(0);
		}
		if (!strcmp(argv[ac], "-dir"))
			if ((++ac) < argc)
				strncpy(baseDir, argv[ac], sizeof(baseDir));
	}	

	if (!excludeMemory)
		searchMemory();
	if (!excludeDisk)
		searchDisk();

	cleanup();
}	
