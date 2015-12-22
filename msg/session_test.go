// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package msg_test

import (
	"bytes"
	"container/heap"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"testing"

	"github.com/mutecomm/mute/cipher"
	"github.com/mutecomm/mute/encode/base64"
	"github.com/mutecomm/mute/keyserver/hashchain"
	"github.com/mutecomm/mute/msg"
	"github.com/mutecomm/mute/msg/session"
	"github.com/mutecomm/mute/msg/session/memstore"
	"github.com/mutecomm/mute/uid"
	"github.com/mutecomm/mute/util/msgs"
	"github.com/mutecomm/mute/util/times"
)

type op int

const (
	encryptAlice op = iota
	encryptBob
	decrypt
)

type operation struct {
	op       op     // operation
	prio     uint64 // priority for decrypt operations
	checkKey bool   // check if message key was deleted
	usePrev  bool   // use previous session for message key check
}

// An item is something we manage in a priority queue.
type item struct {
	priority   uint64    // the priority of the item in the queue
	ciphertext io.Reader // the encrypted message
	plaintext  string    // the decrypted message
	op         op        // the encryption operation
	index      int       // index of the item in the heap, maintained by heap.Interface
}

// A priorityQueue implements heap.Interface and holds items.
type priorityQueue []*item

func (pq priorityQueue) Len() int { return len(pq) }

func (pq priorityQueue) Less(i, j int) bool {
	return pq[i].priority > pq[j].priority
}

func (pq priorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

func (pq *priorityQueue) Push(x interface{}) {
	n := len(*pq)
	item := x.(*item)
	item.index = n
	*pq = append(*pq, item)
}

func (pq *priorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	item.index = -1 // for safety
	*pq = old[0 : n-1]
	return item
}

func generateRun(numOfOps int) ([]*operation, error) {
	var (
		ops        []*operation
		encryptOps int
	)
	for i := 0; i < numOfOps; i++ {
		// determine if we want an encryption or decryption op
		n, err := rand.Int(cipher.RandReader, big.NewInt(2))
		if err != nil {
			return nil, err
		}
		if (encryptOps == 0 || n.Int64() == 0) && (numOfOps-i != encryptOps) {
			// encrypt
			n, err := rand.Int(cipher.RandReader, big.NewInt(2))
			if err != nil {
				return nil, err
			}
			p, err := rand.Int(cipher.RandReader, big.NewInt(9223372036854775807))
			if err != nil {
				return nil, err
			}
			if n.Int64() == 0 {
				ops = append(ops, &operation{op: encryptAlice, prio: p.Uint64()})
			} else {
				ops = append(ops, &operation{op: encryptBob, prio: p.Uint64()})
			}
			encryptOps++
		} else {
			// decrypt
			ops = append(ops, &operation{op: decrypt})
			encryptOps--
		}
	}
	return ops, nil
}

func testRun(r []*operation) error {
	alice := "alice@mute.berlin"
	aliceUID, err := uid.Create(alice, false, "", "", uid.Strict,
		hashchain.TestEntry, cipher.RandReader)
	if err != nil {
		return err
	}
	now := uint64(times.Now())
	aliceKI, _, alicePrivateKey, err := aliceUID.KeyInit(1, now+times.Day, now-times.Day,
		false, "mute.berlin", "", "", cipher.RandReader)
	if err != nil {
		return err
	}
	aliceKE, err := aliceKI.KeyEntryECDHE25519(aliceUID.SigPubKey())
	if err != nil {
		return err
	}

	bob := "bob@mute.berlin"
	bobUID, err := uid.Create(bob, false, "", "", uid.Strict,
		hashchain.TestEntry, cipher.RandReader)
	if err != nil {
		return err
	}
	bobKI, _, bobPrivateKey, err := bobUID.KeyInit(1, now+times.Day, now-times.Day,
		false, "mute.berlin", "", "", cipher.RandReader)
	if err != nil {
		return err
	}
	bobKE, err := bobKI.KeyEntryECDHE25519(bobUID.SigPubKey())
	if err != nil {
		return err
	}

	aliceIdentities := []*uid.Message{aliceUID}
	aliceKeyStore := memstore.New()
	aliceKeyStore.AddPublicKeyEntry(bob, bobKE)
	if err := aliceKE.SetPrivateKey(alicePrivateKey); err != nil {
		return err
	}
	aliceKeyStore.AddPrivateKeyEntry(aliceKE)

	bobIdentities := []*uid.Message{bobUID}
	bobKeyStore := memstore.New()
	bobKeyStore.AddPublicKeyEntry(alice, aliceKE)
	if err := bobKE.SetPrivateKey(bobPrivateKey); err != nil {
		return err
	}
	bobKeyStore.AddPrivateKeyEntry(bobKE)

	var (
		aliceSessionKey string
		bobSessionKey   string
		pq              priorityQueue
	)
	heap.Init(&pq)
	for i := 0; i < len(r); i++ {
		switch {
		case r[i].op == encryptAlice:
			var encMsg bytes.Buffer
			encryptArgs := &msg.EncryptArgs{
				Writer: &encMsg,
				From:   aliceUID,
				To:     bobUID,
				SenderLastKeychainHash: hashchain.TestEntry,
				Reader:                 bytes.NewBufferString(msgs.Message1),
				NumOfKeys:              2,
				Rand:                   cipher.RandReader,
				KeyStore:               aliceKeyStore,
			}
			if _, err = msg.Encrypt(encryptArgs); err != nil {
				return err
			}
			if r[i].checkKey {
				if !r[i].usePrev {
					aliceSessionKey = aliceKeyStore.SessionKey()
				}
				_, err = aliceKeyStore.GetMessageKey(aliceSessionKey, true, 0)
				if err != session.ErrMessageKeyUsed {
					return errors.New("should fail with session.ErrMessageKeyUsed")
				}
			}
			item := &item{
				priority:   r[i].prio,
				ciphertext: &encMsg,
				plaintext:  msgs.Message1,
				op:         encryptAlice,
			}
			heap.Push(&pq, item)
		case r[i].op == encryptBob:
			var encMsg bytes.Buffer
			encryptArgs := &msg.EncryptArgs{
				Writer: &encMsg,
				From:   bobUID,
				To:     aliceUID,
				SenderLastKeychainHash: hashchain.TestEntry,
				Reader:                 bytes.NewBufferString(msgs.Message2),
				NumOfKeys:              2,
				Rand:                   cipher.RandReader,
				KeyStore:               bobKeyStore,
			}
			if _, err = msg.Encrypt(encryptArgs); err != nil {
				return err
			}
			if r[i].checkKey {
				if !r[i].usePrev {
					bobSessionKey = bobKeyStore.SessionKey()
				}
				_, err = bobKeyStore.GetMessageKey(bobSessionKey, true, 0)
				if err != session.ErrMessageKeyUsed {
					return errors.New("should fail with session.ErrMessageKeyUsed")
				}
			}
			item := &item{
				priority:   r[i].prio,
				ciphertext: &encMsg,
				plaintext:  msgs.Message2,
				op:         encryptBob,
			}
			heap.Push(&pq, item)
		case r[i].op == decrypt:
			var res bytes.Buffer
			item := heap.Pop(&pq).(*item)
			switch {
			case item.op == encryptAlice:
				input := base64.NewDecoder(item.ciphertext)
				version, preHeader, err := msg.ReadFirstOuterHeader(input)
				if err != nil {
					return err
				}
				if version != msg.Version {
					return errors.New("wrong version")
				}
				decryptArgs := &msg.DecryptArgs{
					Writer:     &res,
					Identities: bobIdentities,
					PreHeader:  preHeader,
					Reader:     input,
					NumOfKeys:  2,
					Rand:       cipher.RandReader,
					KeyStore:   bobKeyStore,
				}
				_, _, err = msg.Decrypt(decryptArgs)
				if err != nil {
					return err
				}
				if res.String() != item.plaintext {
					return errors.New("messages differ")
				}
				if r[i].checkKey {
					if !r[i].usePrev {
						bobSessionKey = bobKeyStore.SessionKey()
					}
					_, err = bobKeyStore.GetMessageKey(bobSessionKey, false, 0)
					if err != session.ErrMessageKeyUsed {
						return errors.New("should fail with session.ErrMessageKeyUsed")
					}
				}
			case item.op == encryptBob:
				input := base64.NewDecoder(item.ciphertext)
				version, preHeader, err := msg.ReadFirstOuterHeader(input)
				if err != nil {
					return err
				}
				if version != msg.Version {
					return errors.New("wrong version")
				}
				decryptArgs := &msg.DecryptArgs{
					Writer:     &res,
					Identities: aliceIdentities,
					PreHeader:  preHeader,
					Reader:     input,
					NumOfKeys:  2,
					Rand:       cipher.RandReader,
					KeyStore:   aliceKeyStore,
				}
				_, _, err = msg.Decrypt(decryptArgs)
				if err != nil {
					return err
				}
				if res.String() != item.plaintext {
					return errors.New("messages differ")
				}
				if r[i].checkKey {
					if !r[i].usePrev {
						aliceSessionKey = aliceKeyStore.SessionKey()
					}
					_, err = aliceKeyStore.GetMessageKey(aliceSessionKey, false, 0)
					if err != session.ErrMessageKeyUsed {
						return errors.New("should fail with session.ErrMessageKeyUsed")
					}
				}
			}
		}
	}
	return nil
}

func printRun(r []*operation) {
	fmt.Println("[]*operation{")
	for i := 0; i < len(r); i++ {
		switch {
		case r[i].op == encryptAlice:
			fmt.Printf("\t&operation{op: encryptAlice, prio: %d},\n", r[i].prio)
		case r[i].op == encryptBob:
			fmt.Printf("\t&operation{op: encryptBob, prio: %d},\n", r[i].prio)
		case r[i].op == decrypt:
			fmt.Println("\t&operation{op: decrypt},")
		}
	}
	fmt.Println("}")
}

/*
func TestFailure1(t *testing.T) {
	defer log.Flush()
	r := []*operation{
		&operation{op: encryptAlice},
		&operation{op: encryptBob, prio: 2},
		&operation{op: decrypt},
		&operation{op: encryptAlice, prio: 1},
		&operation{op: decrypt},
	}
	if err := testRun(r); err != nil {
		printRun(r)
		t.Error(err)
	}
}
*/

/*
func TestFailure2(t *testing.T) {
	defer log.Flush()
	r := []*operation{
		&operation{op: encryptBob, prio: 1},
		&operation{op: encryptBob, prio: 2},
		&operation{op: encryptBob, prio: 3},
		&operation{op: encryptAlice},
		&operation{op: decrypt},
	}
	if err := testRun(r); err != nil {
		printRun(r)
		t.Error(err)
	}
}
*/

/*
func TestRandom(t *testing.T) {
	defer log.Flush()
	for i := 0; i < 1000; i++ {
		r, err := generateRun(5)
		if err != nil {
			t.Fatal(err)
		}
		if err := testRun(r); err != nil {
			printRun(r)
			t.Fatal(err)
		}
	}
}
*/

/*
func TestConversation(t *testing.T) {
	r := []*operation{
		&operation{op: encryptAlice, checkKey: true},
		&operation{op: decrypt, checkKey: true},
		&operation{op: encryptBob, checkKey: true, usePrev: true},
		&operation{op: decrypt, checkKey: true, usePrev: true},
		&operation{op: encryptAlice, checkKey: true},
		&operation{op: decrypt, checkKey: true},
		&operation{op: encryptBob, checkKey: true, usePrev: true},
		&operation{op: decrypt, checkKey: true, usePrev: true},
	}
	if err := testRun(r); err != nil {
		printRun(r)
		t.Error(err)
	}
}
*/

func TestExhaustSessionSequential(t *testing.T) {
	r := []*operation{
		&operation{op: encryptAlice, prio: 4},
		&operation{op: encryptAlice, prio: 3},
		&operation{op: encryptAlice, prio: 2},
		&operation{op: encryptAlice, prio: 1},
		&operation{op: encryptAlice},
		&operation{op: decrypt},
		&operation{op: decrypt},
		&operation{op: decrypt},
		&operation{op: decrypt},
		&operation{op: decrypt},
	}
	if err := testRun(r); err != nil {
		printRun(r)
		t.Error(err)
	}
}

func TestExhaustSessionLast(t *testing.T) {
	r := []*operation{
		&operation{op: encryptAlice},
		&operation{op: encryptAlice},
		&operation{op: encryptAlice},
		&operation{op: encryptAlice},
		&operation{op: encryptAlice, prio: 1},
		&operation{op: decrypt},
	}
	if err := testRun(r); err != nil {
		printRun(r)
		t.Error(err)
	}
}

/*
func TestSimultaneousSessions(t *testing.T) {
	// simultaneous sessions
	r := []*operation{
		&operation{op: encryptAlice, prio: 1},
		&operation{op: encryptBob},
		&operation{op: decrypt},
		&operation{op: decrypt},
	}
	if err := testRun(r); err != nil {
		printRun(r)
		t.Error(err)
	}
}
*/
