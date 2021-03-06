// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package client

import (
	"fmt"
	"sync"
)

var errorTranslateMap map[string]error
var errorTranslateMutex = new(sync.Mutex)

func registerError(err error) {
	errorTranslateMutex.Lock()
	defer errorTranslateMutex.Unlock()
	if errorTranslateMap == nil {
		errorTranslateMap = make(map[string]error)
	}
	errorTranslateMap[err.Error()] = err
}

func translateError(errStr string) error {
	errorTranslateMutex.Lock()
	defer errorTranslateMutex.Unlock()
	if err, ok := errorTranslateMap[errStr]; ok {
		return err
	}
	return fmt.Errorf("%s", errStr)
}
