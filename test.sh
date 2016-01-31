#!/bin/sh -e

# make sure we test in $GOPATH/src/github.com/mutecomm/mute on Travis
if [ "$TRAVIS" = "true" ] && [ `pwd` != $GOPATH/src/github.com/mutecomm/mute ]
then
  mkdir $GOPATH/src/github.com/mutecomm
  ln -s `pwd` $GOPATH/src/github.com/mutecomm/mute
  cd $GOPATH/src/github.com/mutecomm/mute
fi

# compile everything
echo "compile"
go install -v ./cmd/mutegenerate
go generate ./release
go install -v ./cmd/...

# call source code checker for each directory except doc/ and vendor/
dirs=`ls -d */ | grep -v -e gui -e contrib -e doc -e vendor`
echo "goimports"
for dir in $dirs
do
  test -z "$(goimports -l -w ${dir} | tee /dev/stderr)"
done

echo "golint"
for dir in $dirs
do
  test -z "$(golint ${dir}... | tee /dev/stderr)"
done

echo "go tool vet"
for dir in $dirs
do
  test -z "$(go tool vet ${dir} 2>&1 | tee /dev/stderr)"
done

# call `go test` for every directory with _test.go files
echo "go test"
for dir in $(find -name '*_test.go' -printf '%h\n' | sort -u)
do
  go test -cover $dir
done
