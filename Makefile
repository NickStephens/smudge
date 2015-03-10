all: 
	cd src && $(MAKE) all

package: release/smudge.exe release/smudge64.exe
	touch release/smudge.tar.gz
	rm release/smudge.tar.gz
	tar cvf smudge.tar ../smudge
	gzip smudge.tar
	mv smudge.tar.gz release
