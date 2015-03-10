#include <windows.h>
#include <stdio.h>
#include "smudge.h"

void print_error(char *mesg)
{
	DWORD status;
	LPVOID lpMesgBuf;
	LPVOID lpDisplayBuf;

	status = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS, 
		NULL,
		status,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPSTR) &lpMesgBuf,
		0, NULL);
	printf("%s: %s\n", mesg, lpMesgBuf);
}
