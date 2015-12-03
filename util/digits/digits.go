// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package digits defines helper functions to count the digits of integers.
package digits

// Count returns the digits of u.
func Count(u uint64) int {
	switch {
	case u < 10:
		return 1
	case u < 100:
		return 2
	case u < 1000:
		return 3
	case u < 10000:
		return 4
	case u < 100000:
		return 5
	case u < 1000000:
		return 6
	case u < 10000000:
		return 7
	case u < 100000000:
		return 8
	case u < 1000000000:
		return 9
	case u < 10000000000:
		return 10
	case u < 100000000000:
		return 11
	case u < 1000000000000:
		return 12
	case u < 10000000000000:
		return 13
	case u < 100000000000000:
		return 14
	case u < 1000000000000000:
		return 15
	case u < 10000000000000000:
		return 16
	case u < 100000000000000000:
		return 17
	case u < 1000000000000000000:
		return 18
	case u < 10000000000000000000:
		return 19
	default:
		return 20
	}
}
