
all: 
	i686-w64-mingw32-gcc -o smudge.exe main.c proc.c error.c detect.c -lpsapi
	mv smudge.exe release/
	x86_64-w64-mingw32-gcc -o smudge64.exe main.c proc.c error.c detect.c -lpsapi
	mv smudge64.exe release/

test:
	gcc -o test test.c detect.c error.c

package: smudge.exe
	rm smudge.tar.gz
	tar cvf smudge.tar ../smudge
	gzip smudge.tar
