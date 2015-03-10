
all: 
	gcc -o smudge main.c file.c proc.c error.c detect.c -lpsapi
	mv smudge.exe release/

test:
	gcc -o test test.c detect.c error.c

package: release/smudge.exe release/smudge64.exe
	touch smudge.tar.gz
	rm smudge.tar.gz
	tar cvf smudge.tar ../smudge
	gzip smudge.tar
	mv smudge.tar.gz release
