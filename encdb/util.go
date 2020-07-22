package encdb

import (
	"os"
)

// fileExists checks if filename exists already.
func fileExists(filename string) (bool, error) {
	_, err := os.Stat(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, err
}

// containsString returns true, if the string array sa contains the string s.
// Otherwise, it returns false.
func containsString(sa []string, s string) bool {
	for _, v := range sa {
		if v == s {
			return true
		}
	}
	return false
}
