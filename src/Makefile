ifeq ($(OS), Windows_NT)
	CC64=NOTCONFIGURED
	CC32=gcc
else
	CC64=x86_64-w64-mingw32-gcc
	CC32=i686-w64-mingw32-gcc
endif
	
all: 
ifneq ($(CC64), NOTCONFIGURED)
	$(CC64) -o smudge64.exe main.c file.c proc.c error.c detect.c -lpsapi
	mv smudge64.exe ../release/
endif
	$(CC32) -o smudge.exe main.c file.c proc.c error.c detect.c -lpsapi
	mv smudge.exe ../release/
