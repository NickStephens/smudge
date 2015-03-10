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
	mv smudge64.exe release/
endif
	$(CC32) -o smudge.exe main.c file.c proc.c error.c detect.c -lpsapi
	mv smudge.exe release/

package: release/smudge.exe release/smudge64.exe
	touch release/smudge.tar.gz
	rm release/smudge.tar.gz
	tar cvf smudge.tar ../smudge
	gzip smudge.tar
	mv smudge.tar.gz release
