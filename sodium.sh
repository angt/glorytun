#!/bin/sh

mkdir -p .static
cd .static || exit 1

file=LATEST.tar.gz
url=https://download.libsodium.org/libsodium/releases
dir="$PWD"

[ -f "$file" ] || wget -q     "$url/$file" -O "$file"
[ -f "$file" ] || curl -SsfLO "$url/$file"
[ -f "$file" ] || {
	echo "Couldn't download $url/$file"
	exit 1
}

if [ "$1" ]; then
	mkdir -p "$1"
	cd "$1" || exit 1
fi

rm -rf libsodium-stable
tar zxf "$dir/$file"
cd libsodium-stable || exit 1

./configure ${1+--host=$1} --enable-minimal --disable-dependency-tracking --enable-static --disable-shared
make -j
