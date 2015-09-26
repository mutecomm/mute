// Package util contains utility functions for Mute.
package util

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/mutecomm/mute/log"
)

// ErrNotImplemented is returned if the used functionality is not implemented yet.
//
// TODO: implement everything and remove.
var ErrNotImplemented = errors.New("not implemented")

// Fatal prints err to stderr and exits the process with exit code 1.
func Fatal(err error) {
	fmt.Fprintf(os.Stderr, "%s: error: %s\n", os.Args[0], err)
	os.Exit(1)
}

// Readline reads a single line from the file descriptor fd with given name.
// It closes the file descriptor afterwards.
// Make sure you do not call it multiple times on the same fd!
func Readline(fd int, name string) ([]byte, error) {
	fp := os.NewFile(uintptr(fd), name)
	defer fp.Close()
	scanner := bufio.NewScanner(fp)
	var line []byte
	if scanner.Scan() {
		line = scanner.Bytes()
	} else if err := scanner.Err(); err != nil {
		return nil, log.Error(err)
	}
	return line, nil
}

// CreateDirs creates all given directories.
func CreateDirs(dirs ...string) error {
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return log.Error(err)
		}
	}
	return nil
}

// Cp copies a srcFile to destFile.
func Cp(srcFile, destFile string) error {
	// make sure destination file does not exist already
	if _, err := os.Stat(destFile); err == nil {
		return log.Errorf("destination file '%s' exists already", destFile)
	}
	// open source file
	src, err := os.Open(srcFile)
	if err != nil {
		return err
	}
	defer src.Close()
	// open desination file
	dest, err := os.Create(destFile)
	if err != nil {
		return err
	}
	defer dest.Close()
	// copy content
	if _, err := io.Copy(dest, src); err != nil {
		return err
	}
	return nil
}

// ContainsString returns true, if the the string array sa contains the string s.
// Otherwise, it returns false.
func ContainsString(sa []string, s string) bool {
	for _, v := range sa {
		if v == s {
			return true
		}
	}
	return false
}
