#!/bin/bash -eu

: ${WORKSPACE:="$(pwd)"}

: ${GOPATH:=${WORKSPACE}/.gopath}
if [[ "${GOPATH}" != *:* ]]; then
  mkdir -p "${GOPATH}"
  export PATH="${GOPATH}/bin:${PATH}"
fi
export GOPATH

go get github.com/constabulary/gb/...
go get github.com/golang/lint/golint
go get github.com/tebeka/go2xunit

gb build

set +e

# TODO: Whatever comes out of https://github.com/constabulary/gb/issues/559
GOPATH=$(pwd):$(pwd)/vendor go test $(gb list) -v | go2xunit > results.xml
golint src/... >golint.txt
go tool vet src/ 2>govet.txt
