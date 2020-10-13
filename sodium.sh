#!/bin/sh

set -e
mkdir -p .sodium
cd .sodium

[ -d src ] || {
	FILE=LATEST.tar.gz
	URL=https://download.libsodium.org/libsodium/releases
	[ -f "$FILE" ] \
		|| wget -q     "$URL/$FILE" -O "$FILE" \
		|| curl -SsfLO "$URL/$FILE" || {
		echo "Couldn't download $URL/$FILE"
		exit 1
	}
	tar zxf "$FILE"
	mv libsodium-stable src
}

HOST="${1%-}"
DIR="${HOST:+$HOST-}build"

mkdir -p "$DIR"
cd "$DIR"

../src/configure ${HOST:+--host=$HOST} \
	--disable-dependency-tracking \
	--enable-minimal \
	--enable-static \
	--disable-shared

NPROC=$(sysctl -n hw.ncpu || nproc) 2>/dev/null
make "-j$((NPROC+1))"

cp -a ../src/src/libsodium/include/. src/libsodium/include/
