#!/bin/sh
rm -r licenses
set -e
mkdir -p licenses/github.com/mjl-/ysco
cp LICENSE licenses/github.com/mjl-/ysco/
for p in $(cd vendor && find . -iname '*license*' -or -iname '*licence*' -or -iname '*notice*' -or -iname '*patent*'); do
	(set +e; mkdir -p $(dirname licenses/$p))
	cp vendor/$p licenses/$p
done
