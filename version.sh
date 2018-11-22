#!/bin/sh

export GIT_DIR=.git
export GIT_WORK_TREE=.

[ -z "$VERSION" ] && VERSION="$(git describe --tags --match='v[0-9].*' 2>/dev/null)" \
                  && VERSION="${VERSION#v}"

[ -z "$VERSION" ] && VERSION="$(git rev-parse HEAD 2>/dev/null)"

[ -z "$VERSION" ] && VERSION="$(cat VERSION 2>/dev/null)"

[ -z "$VERSION" ] && VERSION="0.0.0"

printf "%s" "$VERSION" | tee VERSION
