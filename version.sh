#!/bin/sh

[ -z "${VERSION}" ] && VERSION=`git describe --tags --always 2>/dev/null` \
                    && VERSION=${VERSION#v}

[ -z "${VERSION}" ] && VERSION=`basename \`pwd\`` \
                    && VERSION=${VERSION#*-}

[ "$1" = "major"  ] && VERSION=${VERSION%%.*}

printf ${VERSION}
