#!/bin/sh

[ -z "${VERSION}" ] && VERSION=`git describe --tags --match='v[0-9].*' 2>/dev/null` \
                    && VERSION=${VERSION#v}

[ -z "${VERSION}" ] && VERSION=`cat VERSION 2>/dev/null`

[ -z "${VERSION}" ] && VERSION="0.0.0"

[ "$1" = "major"  ] && printf ${VERSION%%.*} \
                    && exit 0

BRANCH=`git rev-parse --abbrev-ref HEAD 2>/dev/null`

[ -n "${BRANCH}" ] && [ "${BRANCH}" != "master" ] \
                   && VERSION=${VERSION}-${BRANCH}

printf ${VERSION} | tee VERSION
