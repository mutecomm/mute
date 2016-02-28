// Copyright (c) 2016 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ctrlengine

import (
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/mutecomm/mute/util/browser"
)

func (ce *CtrlEngine) appStart(statusfp io.Writer, docroot string) error {
	// create listener for a free port
	l, err := net.Listen("tcp", "localhost:")
	if err != nil {
		return err
	}
	// register handlers
	http.Handle("/", http.FileServer(http.Dir(docroot)))
	// start HTTP server
	c := make(chan error)
	go func() {
		c <- http.Serve(l, nil)
	}()
	// try to open browser
	addr := "http://" + l.Addr().String()
	fmt.Fprintf(statusfp, "open browser for address: %s\n", addr)
	if !browser.Start(addr) {
		fmt.Fprintf(statusfp, "could not open browser for address: %s\n", addr)
	}
	return <-c
}
