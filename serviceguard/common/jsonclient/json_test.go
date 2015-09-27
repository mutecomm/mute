// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package jsonclient

import (
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/rpc/v2"
	"github.com/gorilla/rpc/v2/json2"
)

var SSLprivkey = []byte(`-----BEGIN RSA PRIVATE KEY-----                                                                                                                                                                        
MIICXgIBAAKBgQCjXYriAlUzaUo/QyQtfYot+QYB4fG2zquDlDxNaM2FBDnimF2K
VCCqHzaEhHwSSk9Hy7NoPKhk10SZ/qaonZLUVpN1SW9xk0hiCcSIE+czpm96iJ3J
aeeNnz73NRElNaa7MRISiLIMr3U9QfNgC+8AY4Ge5gq3wejw08hhNlSN9wIDAQAB
AoGBAI26hNgJQBOnQAPcYxGYPX4e8mhFtmdrq38u5pYd21eQUAvXNifhTqlpBOo4
6k8P6vIVtmMzZMB/xgN32uykMBHmoJ1/uYLRRm0/ccutRfEbJbWBD0jcpcGYcvsM
FDUlLsWqJkz1G55vhWVsnoZQ94jrZW4auZZ0K2D7BUYuoDupAkEA1LfuR83EHvV0
C7Rin6kEBtT8VvG+Ub9dofRdfV2INBQ/tSDJRN/iSiolmL0oXsJH4W69B7BnF3L7
4L6TOWrFpQJBAMSa6TyFH+aHhEvYDs0zdG49GBrXN+iFoboMUb6Vty10RECF2wFa
I66JYW4l3VcRsCbXkFTn15XIC9IFKDk1imsCQBIOZtiLe9lQ5n/T2QdKdoAJ9j1/
GbOgtdb4gjMRDG23Rk0eslb5ViELgNN9Qv8AKM/W8Y7Eh4uzA/Ro2OBn0s0CQQCy
zDMLEAKH83yUQSSM55ueWb9fQZUdyNHg0i1RRvT0yIT9rP4UB7bllxjdRGA8O+DY
IjinjsUX+XsOgBQpmxCLAkEApNB7zm/HjmUCXApWH8p1/9K12Bmfw0RZSe1RXAcH
vs4ErAvREgTZI69rM7G0aWNCgZp3EcCOCojyj0/HYnE1Sg==
-----END RSA PRIVATE KEY-----`)

var SSLpubkey = []byte(`-----BEGIN CERTIFICATE-----                                                                                                                                                                            
MIICKTCCAZICCQCrEx8ARO4T2TANBgkqhkiG9w0BAQsFADBZMQswCQYDVQQGEwJB
VTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0
cyBQdHkgTHRkMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMTUwNzA3MjAxMTU0WhcN
MjUwNzA0MjAxMTU0WjBZMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0
ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMRIwEAYDVQQDDAls
b2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKNdiuICVTNpSj9D
JC19ii35BgHh8bbOq4OUPE1ozYUEOeKYXYpUIKofNoSEfBJKT0fLs2g8qGTXRJn+
pqidktRWk3VJb3GTSGIJxIgT5zOmb3qInclp542fPvc1ESU1prsxEhKIsgyvdT1B
82AL7wBjgZ7mCrfB6PDTyGE2VI33AgMBAAEwDQYJKoZIhvcNAQELBQADgYEAOMo4
SYjvdRWVBKUb7Z4JKTMCh0atgpcuQEas/pB6CuknjjgsR1E4i/KRvObPyMAViVM7
1xG4PIEoEf1ZDwJSgm0DQ8RFl0FxzdzPojNXjE+Amxua4k5FQBMx0sY6CuY6EME+
bkoy7C5mSfJJiflNsuDvDQWRypHrZMibmzIFC0c=
-----END CERTIFICATE-----`)

func init() {
	s := rpc.NewServer()
	s.RegisterCodec(json2.NewCodec(), "application/json")
	s.RegisterService(new(HelloService), "")
	http.Handle("/", s)
	go http.ListenAndServe("127.0.0.1:9097", nil)
}

type HelloArgs struct {
	Who string
}

type HelloReply struct {
	Message string
}

type HelloService struct{}

func (h *HelloService) Say(r *http.Request, args *HelloArgs, reply *HelloReply) error {
	reply.Message = "Hello, " + args.Who + "!"
	return nil
}

func TestCall(t *testing.T) {
	time.Sleep(time.Second)
	client, err := New("http://127.0.0.1:9097", nil)
	if err != nil {
		t.Fatalf("Count not create: %s", err)
	}
	ret, err := client.JSONRPCRequest("HelloService.Say", HelloArgs{Who: "rigger"})
	if err != nil {
		t.Fatalf("Call err: %s", err)
	}
	if _, ok := ret["Message"]; !ok {
		t.Fatal("No response")
	}
}
