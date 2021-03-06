#include <windows.h>
#include <stdio.h>
#include "smudge.h"
#include "tlds.h"


char *convertToAnsi(wchar_t *in)
{
	char *out;
	char *tout;

	out = malloc(wcslen(in)+1);
	if (out == NULL)	
	{
		print_error("[-] malloc");
		return NULL;
	}
	memset(out, 0, wcslen(in)+1);

	tout = out;
	while(*in)
	{
		*tout = (char) *in;
		tout++; in++;
	}
	tout[wcslen(in)] = 0;

	return out;
}

int inArray(char *needle, char **haystack)
{
	while(*haystack)
	{
		if (!strcasecmp(*haystack, needle))
			return 1;
		haystack++;
	}

	return 0;
}

int isValidTLD(char *tld)
{
	char *temp;
	char *tp;
	char **tldArray;
	int valid = 0;

	temp = strdup(tld);
	if (temp == NULL)
	{
		print_error("[-] malloc");
		return 0;	
	}
	
	tp = temp;
	while(*tp)
	{

		if (!(((*tp >= 0x30) && (*tp <= 0x5a)) || ((*tp >= 0x61) && (*tp <= 0x7a))))
		{
			*tp = 0;
			break;
		}
		tp++;
	}

	if (enableAllTLDs)
		tldArray = TLDs;
	else
		tldArray = CommonTLDs;
	valid = inArray(temp, tldArray);

	free(temp);
	return valid;
}

int isValidDomain(char *str)
{
	char *lastdot = NULL;

	/* no results of the type <emptystring>.<tld> */
	if (*str == '.')
		if (isValidTLD(str+1))
			return 0;

	if (!showCommonNoise)
		if (!strcmp(str, "w.com") || !strcmp(str, "command.com"))
			return 0;

	/* iterate through the string search for a '.' */
	while(*str)
	{
		if (*str == '.')
		{
			str++;
			if (*str != '\0')
				lastdot = str;
			continue;
		}
		if ((*str< 0x30) || (*str> 0x7e)) 
			break;
		str++;
	}
	if (lastdot != NULL)
		return isValidTLD(lastdot);

	return 0;
}

/* very dirty URL test */
int isValidURL(char *str)
{
	return (strstr(str, "http://") || strstr(str, "https://"));
}

int isValidIp(char *str)
{
	char *oct1, *oct2, *oct3, *oct4;
	char **curroct;
	int o1, o2, o3, o4;

	oct1 = oct2 = oct3 = oct4 = NULL;

	curroct = &oct1;
	while(*str)
	{
		if (*curroct == NULL)
		{
			*curroct = str;
		}
		if (*str == '.')
		{
			*str = 0;
			if (oct4 == NULL)
				curroct = &oct4;
			if (oct3 == NULL)
				curroct = &oct3;
			if (oct2 == NULL)
				curroct = &oct2;
			if (oct4 != NULL)
				return 0;
		}
		else if ((*str < 0x30) || (*str > 0x39))
			break;
		str++;
	}

	if ((oct1 == NULL) || (oct2 == NULL) || (oct3 == NULL) || (oct4 == NULL))
	{
		return 0;
	}

	/* another hueristic, if's there's a trailing dot we say it's not
	 * part of an ip addr */
	if (*str  == '.')
		return 0;

	o1 = atoi(oct1);
	o2 = atoi(oct2);
	o3 = atoi(oct3);
	o4 = atoi(oct4);

	/* filter common results that often aren't indicative of anything */
	if (!showCommonNoise)
	{		
		/* localhost */
		if (o1 == 127 && o2 == 0 && o3 == 0 && o4 == 1)	
			return 0;

		/* broadcast address */
		if (o1 == 255 && o2 == 255 && o3 == 255 && o4 == 255)
			return 0;

		/* network identifiers */
		if (o4 == 0)
			return 0;

		/* common version numbers */
		if (o1 == 2 && o2 == 5) //  && ((o3 == 4)||(o3 == 29)))
			return 0;
	}	

	if ((o1 > 0) && (o1 < 256))
		if ((o2 >= 0) && (o2 <= 256))
			if ((o3 >= 0) && (o3 <= 256))
				if ((o4 >= 0) && (o4 <= 256))
				{
					return 1;
				}

	return 0;
}

int isResource(char *str)
{
	int ret = 0;

	if (!disableURLSearch)
		ret |= isValidURL(str);	
	if (!disableDomainSearch)
		ret |= isValidDomain(str);
	if (!disableIPSearch)
		ret |= isValidIp(str);

	return ret;
}
