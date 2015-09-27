// Copyright (c) 2015 Mute Communications Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package times contains time utility functions for Mute.
package times

import (
	"time"
)

// Day defines the number of seconds in a day.
const Day = uint64(24 * 60 * 60)

// Now returns the current time in UTC as Unix time,
// the number of seconds elapsed since January 1, 1970 UTC.
func Now() int64 {
	return time.Now().UTC().Unix()
}

// NowNano returns the current time in UTC as Unix time,
// the number of nanoseconds elapsed since January 1, 1970 UTC.
func NowNano() int64 {
	return time.Now().UTC().UnixNano()
}

// OneYearLater returns the time one year later from now in UTC.
func OneYearLater() int64 {
	return time.Now().UTC().AddDate(1, 0, 0).Unix()
}

// ThirtyDaysLater returns the time 30 days later from now in UTC.
func ThirtyDaysLater() int64 {
	return time.Now().UTC().AddDate(0, 0, 30).Unix()
}

// NinetyDaysLater returns the time 90 days later from now in UTC.
func NinetyDaysLater() int64 {
	return time.Now().UTC().AddDate(0, 0, 90).Unix()
}
