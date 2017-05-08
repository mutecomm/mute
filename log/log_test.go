// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package log_test

import (
	"os"

	"github.com/mutecomm/mute/log"
)

func init() {
	if err := log.Init("info", "log  ", "", true); err != nil {
		panic(err)
	}
}

// This example shows when and how to use the critical log level.
func Example_critical() {
	alwaysFalseCondition := false
	// ...
	if alwaysFalseCondition {
		panic(log.Critical("package name: this condition should never be true"))
	}
}

// This example shows when and how to use the error log level.
func Example_error() {
	conditionWhichShouldBeTrue := true
	// ...

	// create own error
	if !conditionWhichShouldBeTrue {
		log.Error("package name: condition should be true")
	}

	// calling external package which can produce an error
	_, err := os.Create("filename")
	if err != nil {
		log.Error(err)
	}
}

// This example shows when and how to use the warn log level.
func Example_warn() {
	expiryCondition := true
	// ...

	// check condition in server package, error is not handled on the server
	if !expiryCondition {
		log.Warnf("server: token has expired")
	}
}

// This example shows when and how to use the info log level.
func Example_info() {
	// server receives message
	log.Info("server: message received")
}
