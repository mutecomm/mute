// Copyright (c) 2013 Conformal Systems LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package interrupt allows to handle interrupts.
package interrupt

import (
	"os"
	"os/signal"

	"github.com/mutecomm/mute/log"
)

// ShutdownChannel is used to signal that shutdown is in progress.
var ShutdownChannel = make(chan error)

// interruptChannel is used to receive SIGINT (Ctrl+C) signals.
var interruptChannel chan os.Signal

// addHandlerChannel is used to add an interrupt handler to the list of handlers
// to be invoked on SIGINT (Ctrl+C) signals.
var addHandlerChannel = make(chan func())

// mainInterruptHandler listens for SIGINT (Ctrl+C) signals on the
// interruptChannel and invokes the registered interruptCallbacks accordingly.
// It also listens for callback registration.  It must be run as a goroutine.
func mainInterruptHandler() {
	// interruptCallbacks is a list of callbacks to invoke when a
	// SIGINT (Ctrl+C) is received.
	var interruptCallbacks []func()

	for {
		select {
		case <-interruptChannel:
			log.Infof("received SIGINT (Ctrl+C). Shutting down...")
			for _, callback := range interruptCallbacks {
				callback()
			}

			// Signal the main goroutine to shutdown.
			ShutdownChannel <- nil

		case handler := <-addHandlerChannel:
			interruptCallbacks = append(interruptCallbacks, handler)
		}
	}
}

// AddInterruptHandler adds a handler to call when a SIGINT (Ctrl+C) is
// received.
func AddInterruptHandler(handler func()) {
	// Create the channel and start the main interrupt handler which invokes
	// all other callbacks and exits if not already done.
	if interruptChannel == nil {
		interruptChannel = make(chan os.Signal, 1)
		signal.Notify(interruptChannel, os.Interrupt)
		go mainInterruptHandler()
	}

	addHandlerChannel <- handler
}
