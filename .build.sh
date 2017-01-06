#!/bin/sh

export CC="gcc -static"

git clone https://github.com/jedisct1/libsodium --depth=1 --branch stable
cd libsodium || exit 1
./autogen.sh && ./configure --enable-minimal --disable-shared --prefix=/usr && make install
cd ..

./autogen.sh && ./configure && make
[ -x glorytun ] || exit 1

mkdir -p deploy

cp glorytun deploy/glorytun-$(cat VERSION)-$(uname -m).debug.bin

strip -s glorytun
cp glorytun deploy/glorytun-$(cat VERSION)-$(uname -m).bin
