char *stringBason;
DWORD stringBasonSz;

int searchMemory(void);
int searchDisk(void);
void print_error(char *mesg);
int isResource(char *s);

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
char baseDir[MAX_PATH];
