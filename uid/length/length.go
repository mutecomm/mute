// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package length defines the JSON encoded lengths of some uid datastructures
// (for padding purposes).
package length

// KeyEntryECDHE25519 defines the length of a JSON encoded uid.KeyEntry with
// FUNCTION "ECDHE25519".
const KeyEntryECDHE25519 = 247

// Nil defines the length of a JSON encoded nil value.
const Nil = 4
