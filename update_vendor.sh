#!/bin/sh -ex

go get -u -v github.com/kardianos/govendor
rm -rf vendor
go get -u -v -t ./...
govendor init
govendor add +external
