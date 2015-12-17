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
	"github.com/mutecomm/mute/log"
	"github.com/mutecomm/mute/msg"
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
	op   op     // operation
	prio uint64 // priority for decrypt operations
}

// An Item is something we manage in a priority queue.
type Item struct {
	priority   uint64 // The priority of the item in the queue.
	ciphertext io.Reader
	plaintext  string
	op         op
	// The index is needed by update and is maintained by the heap.Interface methods.
	index int // The index of the item in the heap.
}

// A PriorityQueue implements heap.Interface and holds Items.
type PriorityQueue []*Item

func (pq PriorityQueue) Len() int { return len(pq) }

func (pq PriorityQueue) Less(i, j int) bool {
	// We want Pop to give us the highest, not lowest, priority so we use greater than here.
	return pq[i].priority > pq[j].priority
}

func (pq PriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

func (pq *PriorityQueue) Push(x interface{}) {
	n := len(*pq)
	item := x.(*Item)
	item.index = n
	*pq = append(*pq, item)
}

func (pq *PriorityQueue) Pop() interface{} {
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

	aliceIdentities := []string{aliceUID.Identity()}
	aliceRecipientIdentities := []*uid.KeyEntry{aliceUID.PubKey()}
	aliceKeyStore := memstore.New()
	aliceKeyStore.AddPublicKeyEntry(bob, bobKE)
	if err := aliceKE.SetPrivateKey(alicePrivateKey); err != nil {
		return err
	}
	aliceKeyStore.AddPrivateKeyEntry(aliceKE)

	bobIdentities := []string{bobUID.Identity()}
	bobRecipientIdentities := []*uid.KeyEntry{bobUID.PubKey()}
	bobKeyStore := memstore.New()
	bobKeyStore.AddPublicKeyEntry(alice, aliceKE)
	if err := bobKE.SetPrivateKey(bobPrivateKey); err != nil {
		return err
	}
	bobKeyStore.AddPrivateKeyEntry(bobKE)

	var pq PriorityQueue
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
			item := &Item{
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
			item := &Item{
				priority:   r[i].prio,
				ciphertext: &encMsg,
				plaintext:  msgs.Message2,
				op:         encryptBob,
			}
			heap.Push(&pq, item)
		case r[i].op == decrypt:
			var res bytes.Buffer
			item := heap.Pop(&pq).(*Item)
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
					Writer:              &res,
					Identities:          bobIdentities,
					RecipientIdentities: bobRecipientIdentities,
					PreHeader:           preHeader,
					Reader:              input,
					NumOfKeys:           2,
					Rand:                cipher.RandReader,
					KeyStore:            bobKeyStore,
				}
				_, _, err = msg.Decrypt(decryptArgs)
				if err != nil {
					return err
				}
				if res.String() != item.plaintext {
					return errors.New("messages differ")
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
					Writer:              &res,
					Identities:          aliceIdentities,
					RecipientIdentities: aliceRecipientIdentities,
					PreHeader:           preHeader,
					Reader:              input,
					NumOfKeys:           2,
					Rand:                cipher.RandReader,
					KeyStore:            aliceKeyStore,
				}
				_, _, err = msg.Decrypt(decryptArgs)
				if err != nil {
					return err
				}
				if res.String() != item.plaintext {
					return errors.New("messages differ")
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

func TestRandom(t *testing.T) {
	defer log.Flush()
	/*
		for i := 0; i < 100; i++ {
			r, err := generateRun(100)
			if err != nil {
				t.Fatal(err)
			}
			if err := testRun(r); err != nil {
				printRun(r)
				t.Error(err)
			}
		}
	*/
	r := []*operation{
		&operation{op: encryptAlice},
		&operation{op: decrypt},
		&operation{op: encryptBob},
		&operation{op: decrypt},
	}
	if err := testRun(r); err != nil {
		printRun(r)
		t.Error(err)
	}
}

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
