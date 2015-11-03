package sqlite3

/*
// enable encryption codec in sqlite
#cgo CFLAGS: -DSQLITE_HAS_CODEC

// use memory for temporay storage in sqlite
#cgo CFLAGS: -DSQLITE_TEMP_STORE=2

// use libtomcrypt implementation in sqlcipher
#cgo CFLAGS: -DSQLCIPHER_CRYPTO_LIBTOMCRYPT

// disable loadable extensions in sqlite
#cgo CFLAGS: -DSQLITE_OMIT_LOAD_EXTENSION=1

// make libtomcrypt thread-safe
#cgo CFLAGS: -DLTC_PTHREAD

// disable assertions
#cgo CFLAGS: -DNDEBUG

// set operating specific sqlite flags
#cgo linux CFLAGS: -DSQLITE_OS_UNIX=1
#cgo windows CFLAGS: -DSQLITE_OS_WIN=1
*/
import "C"
