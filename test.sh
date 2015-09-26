#!/bin/sh -e

# call source code checker for each directory except doc/ and vendor/
dirs=`ls -d */ | grep -v doc | grep -v vendor`
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
echo "go testestt"
for dir in $(find -name '*_test.go' -printf '%h\n' | sort -u)
do
  go test -cover $dir
done
