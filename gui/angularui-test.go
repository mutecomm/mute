// Copyright (c) 2016 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Provide test server for angular ui
package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"time"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("%s <port> <path>\n", os.Args[0])
		os.Exit(1)
	}
	_, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Printf("port: \"%s\" not a valid number\n", os.Args[1])
		os.Exit(1)
	}
	datapath := os.Args[2]
	muxer := http.NewServeMux()
	muxer.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("===== Call begin =====")
		fmt.Printf("%s %s\n", r.Method, r.URL)
		fmt.Println("Headers:")
		for k, v := range r.Header {
			fmt.Printf("    %s: %s\n", k, v)
		}
		if r.Method == "GET" {
			// Return file from path
			urlParsed, _ := url.ParseRequestURI(r.RequestURI)
			if urlParsed.Path == "" || urlParsed.Path == "/" {
				urlParsed.Path = "index.html"
			}
			filename := path.Join(datapath, urlParsed.Path)
			content, err := ioutil.ReadFile(filename)
			if err != nil {
				fmt.Printf("\"%s\": %s\n", filename, err)
				w.Write([]byte("{ \"status\": \"error\" }"))
			} else {
				fmt.Printf("Serving: \"%s\"\n", filename)
				w.Write(content)
			}
		} else {
			// Print
			if r.ContentLength > 0 {
				body := make([]byte, r.ContentLength)
				io.ReadFull(r.Body, body)
				fmt.Printf("===== Body begin =====\n%s\n===== Body end =====\n", body)
			}
			w.Write([]byte("{ \"status\": \"ok\" }"))
		}
		fmt.Printf("===== Call end =====\n\n\n\n")
	})
	s := &http.Server{
		Addr:           ":" + os.Args[1],
		Handler:        muxer,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MB
	}

	log.Fatal(s.ListenAndServe())
}
