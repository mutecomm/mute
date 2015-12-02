// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package identity

import (
	"strings"
	"testing"
)

func TestMap(t *testing.T) {
	if _, err := Map("john.doe"); err == nil {
		t.Error("should fail")
	}

	// legal identity
	id, err := Map("john.doe@mute.berlin")
	if err != nil || id != "iohn.doe@mute.berlin" {
		t.Error("id != \"iohn.doe@mute.berlin\"")
	}

	if _, err := Map("john..doe@mute.berlin"); err == nil {
		t.Error("should fail")
	}
}

func TestIsMapped(t *testing.T) {
	// not well-formed
	if err := IsMapped("john.doe"); err != ErrNotMapped {
		t.Error("err != ErrNotMapped")
	}
	// not mapped
	if err := IsMapped("john.doe@mute.berlin"); err != ErrNotMapped {
		t.Error("err != ErrNotMapped")
	}
	// mapped
	if err := IsMapped("iohn.doe@mute.berlin"); err != nil {
		t.Error("should be mapped")
	}
}

func TestMapPlus(t *testing.T) {
	if _, _, err := MapPlus("john.doe"); err == nil {
		t.Error("should fail")
	}

	// legal identity
	id, domain, err := MapPlus("john.doe@MUTE.BERLIN")
	if err != nil || id != "iohn.doe@mute.berlin" || domain != "mute.berlin" {
		t.Error("should not fail")
	}

	if _, _, err := MapPlus("john..doe@mute.berlin"); err == nil {
		t.Error("should fail")
	}
}

func TestMapLocalpart(t *testing.T) {
	// legal name
	lp, err := MapLocalpart("max.mustermann")
	if err != nil || lp != "max.mustermann" {
		t.Error("should not fail")
	}

	// legal name (some mapping going on)
	lp, err = MapLocalpart("John-Doe")
	if err != nil || lp != "iohn-doe" {
		t.Error("should not fail")
	}

	// too short
	lp, err = MapLocalpart("dj")
	if err == nil {
		t.Error("shold fail")
	}

	// '-' and '.' stuff
	if _, err := MapLocalpart("-max"); err == nil {
		t.Error("should fail")
	}
	if _, err := MapLocalpart(".max"); err == nil {
		t.Error("should fail")
	}

	if _, err := MapLocalpart("max-"); err == nil {
		t.Error("should fail")
	}
	if _, err := MapLocalpart("max."); err == nil {
		t.Error("should fail")
	}

	if _, err := MapLocalpart("max--mustermann"); err == nil {
		t.Error("should fail")
	}
	if _, err := MapLocalpart("max-.mustermann"); err == nil {
		t.Error("should fail")
	}
	if _, err := MapLocalpart("max.-mustermann"); err == nil {
		t.Error("should fail")
	}
	if _, err := MapLocalpart("max..mustermann"); err == nil {
		t.Error("should fail")
	}

	// illegal character
	if _, err := MapLocalpart("max@mustermann"); err == nil {
		t.Error("should fail")
	}

	// mappings
	lp, err = MapLocalpart("john012")
	if err != nil || lp != "iohnol2" {
		t.Error("should not fail")
	}

	// too long
	lp, err = MapLocalpart("abcdefghijklmnopqrstuvwzyz.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-X")
	if err == nil {
		t.Error("should fail")
	}
}

func TestMapDomain(t *testing.T) {
	if MapDomain("mute.berlin") != "mute.berlin" {
		t.Error("should map correctly")
	}
	if MapDomain("Mute.Berlin") != "mute.berlin" {
		t.Error("should map correctly")
	}
	if MapDomain("MUTE.BERLIN") != "mute.berlin" {
		t.Error("should map correctly")
	}
}

func TestSplit(t *testing.T) {
	// no '@'
	if _, _, err := Split("john.doe"); err == nil {
		t.Error("should fail")
	}

	// one '@'
	lp, domain, err := Split("john.doe@mute.berlin")
	if err != nil || lp != "john.doe" || domain != "mute.berlin" {
		t.Error("should not fail")
	}

	// two '@'
	if _, _, err := Split("john.doe@mute@berlin"); err == nil {
		t.Error("should fail")
	}
}

func TestMaxLen(t *testing.T) {
	longID := strings.Repeat(".", MaxLen+1)
	if _, err := Map(longID); err != ErrTooLong {
		t.Error("Map(longID) should fail with ErrTooLong")
	}
	if _, _, err := MapPlus(longID); err != ErrTooLong {
		t.Error("MapPlu(longID) should fail with ErrTooLong")
	}
}
