char *stringBason;
DWORD stringBasonSz;
wchar_t *wideStringBason;
DWORD wideStringBasonSz;

int searchMemory(void);
int searchDisk(void);
void print_error(char *mesg);
int isResource(char *s);

char *convertToAnsi(wchar_t *);

/* options */
int verbose;
int excludeDisk;
int excludeMemory;
int disableDomainSearch;
int disableURLSearch;
int disableIPSearch;
int enableAllTLDs;
int processArchival;
int aggressive;
int showCommonNoise;
char baseDir[MAX_PATH];
