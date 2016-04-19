// Copyright (c) 2016 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ctrlengine

import (
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/codegangsta/cli"
	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/util/browser"
)

var loginTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Mute</title>
</head>
<body>
<h2>Unlock Mute DB</h2>
<form action="/login" method="post">
    Passphrase:<input autofocus type="password" name="passphrase">
    <input type="submit" value="unlock">
</form>
</body>
</html>
`

var t = template.Must(template.New("login").Parse(loginTemplate))

var auth struct {
	sync.RWMutex
	secret string
}

type loginHandler struct {
	ce       *CtrlEngine
	c        *cli.Context
	statusfp io.Writer
}

func (lh *loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		if err := t.Execute(w, nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		passphrase := r.Form["passphrase"][0]
		lh.ce.passphrase = []byte(passphrase)
		if err := lh.ce.prepare(lh.c, true, true); err != nil {
			// TODO: allow to input passphrase again
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		fmt.Fprintln(lh.statusfp, "successful login")

		// set cookie
		secret := cipher.RandPass(cipher.RandReader)
		auth.Lock()
		auth.secret = secret
		auth.Unlock()
		cookie := &http.Cookie{
			Name:    "mute",
			Value:   secret,
			Path:    "/",
			Expires: time.Now().UTC().AddDate(0, 0, 30),
		}
		http.SetCookie(w, cookie)

		// redirect to SPA
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

type staticHandler struct {
	handler http.Handler
}

func (sh *staticHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// check authentication via cookie
	//
	// TODO: transform this into a generic authentication wrapper which can be
	// reused for other handlers
	cookie, err := r.Cookie("mute")
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	var secret string
	auth.RLock()
	secret = auth.secret
	auth.RUnlock()
	// check that cookie has been set and equals random secret
	if cookie.Value != "" && cookie.Value != secret {
		http.Error(w, "invalid cookie value", http.StatusForbidden)
		return
	}

	// serve static page
	sh.handler.ServeHTTP(w, r)
}

func (ce *CtrlEngine) appStart(
	c *cli.Context,
	statusfp io.Writer,
	docroot string,
) error {
	// create listener for a free port
	// TODO: do we want to use a fixed port here?
	l, err := net.Listen("tcp", "localhost:")
	if err != nil {
		return err
	}
	// create muxer
	muxer := http.NewServeMux()
	// register handlers
	muxer.Handle("/", &staticHandler{
		handler: http.FileServer(http.Dir(docroot)),
	})
	muxer.Handle("/login", &loginHandler{
		ce:       ce,
		c:        c,
		statusfp: statusfp,
	})
	// create HTTP server
	srv := &http.Server{
		Handler:        muxer,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MB
	}
	// start HTTP server
	ch := make(chan error)
	go func() {
		ch <- srv.Serve(l)
	}()
	// try to open browser
	addr := "http://" + l.Addr().String() + "/login"
	fmt.Fprintf(statusfp, "open browser for address: %s\n", addr)
	if !browser.Start(addr) {
		fmt.Fprintf(statusfp, "could not open browser for address: %s\n", addr)
	}
	return <-ch
}
