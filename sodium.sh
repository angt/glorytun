#!/bin/sh

file=LATEST.tar.gz
url=https://download.libsodium.org/libsodium/releases

[ -f "$file" ] || wget -q     "$url/$file" -O "$file"
[ -f "$file" ] || curl -SsfLO "$url/$file"
[ -f "$file" ] || {
	echo "Couldn't download $url/$file"
	exit 1
}

rm -rf libsodium-stable
tar zxf "$file"
cd libsodium-stable || exit 1

./configure --enable-minimal --disable-dependency-tracking --enable-static --disable-shared
make -j
