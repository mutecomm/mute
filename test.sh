#!/bin/sh -e

# call source code checker for each directory except doc/ and vendor/
for dir in $(ls -d */ | grep -v doc | grep -v vendor)
do
  test -z "$(goimports -l -w ${dir} | tee /dev/stderr)"
  test -z "$(golint ${dir}... | tee /dev/stderr)"
  test -z "$(go tool vet ${dir} 2>&1 | tee /dev/stderr)"
done

# call `go test` for every directory with _test.go files
for dir in $(find -name '*_test.go' -printf '%h\n' | sort -u)
do
  go test -cover $dir
done
