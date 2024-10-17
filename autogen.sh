#!/bin/bash

printf 'cleaning up .'

[[ -f Makefile ]] && make clean

# Clean up the generated crud
for F in compile config.guess config.sub depcomp install-sh ltmain.sh missing \
	mkinstalldirs Makefile.in Makefile config.log config.status libtool stamp-h1
do
    [[ -f $F ]] && rm -f "$F"
	printf .
done

for F in aclocal.m4 configure configure~ config.h.in config.h \
	aclocal/{libtool.m4,ltoptions.m4,ltsugar.m4,ltversion.m4,lt~obsolete.m4} \
	*.gz
do
	[[ -f $F ]] && rm -f "$F"
	printf .
done

for D in autom4te.cache build-aux .libs .deps aclocal; do
    [[ -d $D ]] && rm -rf "$D"
	printf .
done

printf ' done.\n'

[[ $1 == "clean" ]] && exit

[[ -d aclocal ]] || mkdir aclocal
aclocal -I aclocal
libtoolize --force --copy
autoheader
automake --add-missing --copy --gnu # -Wall
autoconf # -Wall
