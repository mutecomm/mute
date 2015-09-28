## Mute — secure messaging [![GoDoc](https://godoc.org/github.com/mutecomm/mute?status.png)](http://godoc.org/github.com/mutecomm/mute) [![Build Status](https://travis-ci.org/mutecomm/mute.png)](https://travis-ci.org/mutecomm/mute)

This is an **alpha** release of Mute — **use at your own risk**!
At the moment, you can only test the command-line interface `mutectrl`, a full
UI will be released at a later stage.


### Features

- End-to-end encryption.
- Communication with forward secrecy (keys required to decrypt past messages
  are frequently replaced and destroyed).
- Establish forward secret communication with first message (no synchronous
  two-way handshake).
- Asynchronous communication between peers.
- Authenticity of the identity-key relationship is established and preserved.
- Human-readable/human-memorizable identities.
- Communication with established standards where possible (e.g., using SMTP as
  the transport protocol).
- Sending messages and changing the state of one's own identity requires
  payment by the user to both finance the system and to limit SPAM.
- Plausible deniability of message content and some deniability of
  communication relationship.


### Installation

At the moment, only installation from source is supported.
You should have at least [Go 1.5](https://golang.org/dl/) installed (with `GOPATH` set accordingly and `$GOPATH/bin` being part of your `PATH`).
The environment variable `GO15VENDOREXPERIMENT` should be set to `1`, to make
sure that Mute uses the external dependencies from the `vendor/` directory.

To install `mutectrl` execute the following three commands:

```
go install github.com/mutecomm/mute/cmd/mutegenerate
go generate github.com/mutecomm/mute/release
go install github.com/mutecomm/mute/cmd/...
```


### Setup


TODO:
- How to setup `mutectrl`? (DB password, creating nym)
- How to get tokens?


### Updates


TODO:
- How to update `mutectrl` from source?
- Why frequent updates are important.


### Backups

TODO:
- Which files to backup to make sure you do not loose keys and messages.


### Specification documents

- [Overview](overview.md)
- [Keyserver design](keyserver.md)
- [Example of a complete Keyserver use-case](keyserver-usecase.md)
- [Message protocol](messages.md)
- [Ciphersuites](ciphers.md)
- [Account server](accountserver.md)
