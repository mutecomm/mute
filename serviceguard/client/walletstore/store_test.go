package walletstore

import (
	"bytes"
	"database/sql"
	"fmt"
	"os"
	"path"
	"strconv"
	"testing"

	"github.com/agl/ed25519"
	_ "github.com/mutecomm/go-sqlcipher"
	"github.com/mutecomm/mute/serviceguard/client"
	"github.com/mutecomm/mute/util/times"
)

const testExpire = int64(24 * 3600 * 14)

var testDB = "root@/wallet"
var sqliteDB = path.Join(os.TempDir(), "walletDB-"+strconv.FormatInt(times.Now(), 10)+".db")
var testOwnerPub = [ed25519.PublicKeySize]byte{0x00, 0x01, 0x02}
var testOwnerPriv = [ed25519.PrivateKeySize]byte{0x00, 0x02, 0x02}
var testNewOwnerPub = [ed25519.PublicKeySize]byte{0x00, 0x03, 0x02}
var testNewOwnerPriv = [ed25519.PrivateKeySize]byte{0x00, 0x04, 0x02}
var testOwnerPubCount1 = [ed25519.PublicKeySize]byte{0x00, 0x01, 0x02, 0x01}
var testOwnerPubCount2 = [ed25519.PublicKeySize]byte{0x00, 0x01, 0x02, 0x02}
var testData = &client.TokenEntry{
	Hash:            []byte("TokenHash"),
	Token:           []byte("TokenData"),
	OwnerPubKey:     &testOwnerPub,
	OwnerPrivKey:    &testOwnerPriv,
	Renewable:       true,
	CanReissue:      true,
	Usage:           "Testing",
	Expire:          times.Now() + testExpire + 10,
	Params:          []byte("TestParams"),
	ServerPacket:    []byte("TestServerPacket"),
	BlindingFactors: []byte("TestBlindingFactor"),
	NewOwnerPubKey:  &testNewOwnerPub,
	NewOwnerPrivKey: &testNewOwnerPriv,
}
var testData2 = &client.TokenEntry{
	Hash:         []byte("TokenHash2"),
	Token:        []byte("TokenData2"),
	OwnerPubKey:  &testOwnerPub,
	OwnerPrivKey: &testOwnerPriv,
	Renewable:    true,
	CanReissue:   true,
	Usage:        "Testing",
	Expire:       times.Now() + testExpire + 20,
	Params:       []byte("TestParams"),
}
var testData3 = &client.TokenEntry{
	Hash:        []byte("TokenHash3"),
	Token:       []byte("TokenData3"),
	OwnerPubKey: &testOwnerPub,
	Renewable:   true,
	CanReissue:  true,
	Usage:       "Testing",
	Expire:      times.Now() + testExpire + 30,
	Params:      []byte("TestParams"),
}
var testData4 = &client.TokenEntry{
	Hash:        []byte("TokenHash4"),
	Token:       []byte("TokenData4"),
	OwnerPubKey: &testOwnerPub,
	Renewable:   true,
	CanReissue:  true,
	Usage:       "Testing",
	Expire:      times.Now() + testExpire + 40,
	Params:      []byte("TestParams"),
}
var testData5 = &client.TokenEntry{
	Hash:         []byte("TokenHash5-Expire"),
	Token:        []byte("TokenData5"),
	OwnerPubKey:  &testOwnerPub,
	OwnerPrivKey: &testOwnerPriv,
	Renewable:    true,
	CanReissue:   true,
	Usage:        "Testing",
	Expire:       times.Now(),
}
var testData6 = &client.TokenEntry{
	Hash:            []byte("TokenHash6-Reissue"),
	Token:           []byte("TokenData6"),
	OwnerPubKey:     &testOwnerPub,
	OwnerPrivKey:    &testOwnerPriv,
	Renewable:       true,
	CanReissue:      true,
	Usage:           "Testing",
	Expire:          times.Now(),
	ServerPacket:    []byte("TestServerPacket"),
	BlindingFactors: []byte("TestBlindingFactor"),
	NewOwnerPubKey:  &testNewOwnerPub,
	NewOwnerPrivKey: &testNewOwnerPriv,
}

var testData7 = &client.TokenEntry{
	Hash:         []byte("TokenHash7-Count"),
	Token:        []byte("TokenData7"),
	OwnerPubKey:  &testOwnerPub,
	OwnerPrivKey: &testOwnerPriv,
	Renewable:    true,
	CanReissue:   true,
	Usage:        "Count",
	Expire:       times.Now(),
}
var testData8 = &client.TokenEntry{
	Hash:         []byte("TokenHash8-Count"),
	Token:        []byte("TokenData8"),
	OwnerPubKey:  &testOwnerPub,
	OwnerPrivKey: &testOwnerPriv,
	Renewable:    true,
	CanReissue:   true,
	Usage:        "Count",
	Expire:       times.Now(),
}
var testData9 = &client.TokenEntry{
	Hash:        []byte("TokenHash9-Count"),
	Token:       []byte("TokenData9"),
	OwnerPubKey: &testOwnerPubCount1,
	Renewable:   true,
	CanReissue:  true,
	Usage:       "Count",
	Expire:      times.Now(),
}
var testData10 = &client.TokenEntry{
	Hash:        []byte("TokenHash10-Count"),
	Token:       []byte("TokenData10"),
	OwnerPubKey: &testOwnerPubCount2,
	Renewable:   true,
	CanReissue:  true,
	Usage:       "Count",
	Expire:      times.Now(),
}
var testData11 = &client.TokenEntry{
	Hash:        []byte("TokenHash11-Count"),
	Token:       []byte("TokenData11"),
	OwnerPubKey: &testOwnerPubCount2,
	Renewable:   true,
	CanReissue:  true,
	Usage:       "Count",
	Expire:      times.Now(),
}
var testData12 = &client.TokenEntry{
	Hash:        []byte("TokenHash12-Expire"),
	Token:       []byte("TokenData12"),
	OwnerPubKey: &testOwnerPubCount2,
	Renewable:   true,
	CanReissue:  true,
	Usage:       "Expire",
	Expire:      times.Now() - ExpireEdge - 10,
}

func TestMysqlDB(t *testing.T) {
	db, err := NewFromURL(testDB)
	if err != nil {
		t.Fatalf("DB Create failed: %s", err)
	}
	db.DelToken(testData.Hash)
	db.DelToken(testData2.Hash)
	db.DelToken(testData3.Hash)
	db.DelToken(testData4.Hash)
	db.DelToken(testData5.Hash)
	db.DelToken(testData6.Hash)
	db.DelToken(testData7.Hash)
	db.DelToken(testData8.Hash)
	db.DelToken(testData9.Hash)
	db.DelToken(testData10.Hash)
	db.DelToken(testData11.Hash)
	err = db.SetToken(*testData)
	if err != nil {
		t.Errorf("SetToken failed: %s", err)
	}
	db.SetToken(*testData2)
	db.SetToken(*testData3)
	db.SetToken(*testData4)
	db.CleanLocks(true)
	lockID := db.LockToken(testData.Hash)
	if lockID <= 0 {
		t.Error("Lock failed")
	}
	lockID2 := db.LockToken(testData.Hash)
	if lockID2 > 0 {
		t.Error("Lock MUST fail")
	}
	db.UnlockToken(testData.Hash)
	lockID = db.LockToken(testData.Hash)
	if lockID <= 0 {
		t.Error("Unlock failed")
	}
	testDataResult, err := db.GetToken(testData.Hash, -1)
	if err != nil {
		t.Errorf("GetToken failed: %s", err)
	}
	err = compareTestData(testData, testDataResult)
	if err != nil {
		t.Errorf("%s", err)
	}
	_, err = db.GetToken(testData.Hash, 0)
	if err == nil || err != client.ErrLocked {
		t.Errorf("GetToken MUST fail with ErrLocked: %s", err)
	}
	_, err = db.GetToken(testData.Hash, lockID)
	if err != nil {
		t.Errorf("GetToken failed on locked token: %s", err)
	}
	db.UnlockToken(testData.Hash)
	testData.Expire = times.Now() + 3600*300*24
	testData.NewOwnerPubKey = nil
	err = db.SetToken(*testData)
	if err != nil {
		t.Errorf("SetToken Update failed: %s", err)
	}
	err = db.SetAuthToken([]byte("testing authtoken"), 2)
	if err != nil {
		t.Errorf("SetAuthToken failed: %s", err)
	}
	token, tries := db.GetAuthToken()
	if string(token) != "testing authtoken" || tries != 2 {
		t.Errorf("GetAuthToken failed: %s != %s || %d != %d", token, "testing authtoken", tries, 2)
	}
	verifyKey := [ed25519.PublicKeySize]byte{0x01, 0x02, 0x03}
	verifyKeys := make([][ed25519.PublicKeySize]byte, 0, 1)
	verifyKeys = append(verifyKeys, verifyKey)
	db.SetVerifyKeys(verifyKeys)
	verifyKeys = db.GetVerifyKeys()
	if verifyKeys[0] != verifyKey {
		t.Error("Set/GetVerifyKeys wrong data")
	}
	testDataResult, err = db.FindToken(testData.Usage)
	if err != nil {
		t.Errorf("FindToken failed: %s", err)
	}
	err = compareTestData(testData2, testDataResult)
	if err != nil {
		t.Errorf("%s", err)
	}
	testDataResult, err = db.GetAndLockToken(testData.Usage, testData.OwnerPubKey)
	if err != nil {
		t.Errorf("GetAndLockToken failed: %s", err)
	}
	err = compareTestData(testData3, testDataResult)
	if err != nil {
		t.Errorf("%s", err)
	}
	testDataResult, err = db.GetAndLockToken(testData.Usage, nil)
	if err != nil {
		t.Errorf("GetAndLockToken failed: %s", err)
	}
	err = compareTestData(testData4, testDataResult)
	if err != nil {
		t.Errorf("%s", err)
	}
	db.SetToken(*testData5)
	expireToken := db.GetExpire()
	if expireToken == nil {
		t.Error("Expiring token not found")
	}
	if !bytes.Equal(expireToken, testData5.Hash) {
		t.Errorf("Wrong expire-token found: %s", string(expireToken))
	}
	db.SetToken(*testData6)
	reissueToken := db.GetInReissue()
	if reissueToken == nil {
		t.Error("Reissue-Token not found")
	}
	if !bytes.Equal(reissueToken, testData6.Hash) {
		t.Errorf("Wrong reissue-token found: %s", string(reissueToken))
	}
	db.SetToken(*testData7)
	db.SetToken(*testData8)
	db.SetToken(*testData9)
	db.SetToken(*testData10)
	db.SetToken(*testData11)
	count := db.GetBalanceOwn("Count")
	if count != 2 {
		t.Errorf("GetBalanceOwn wrong count: %d != %d", 2, count)
	}
	count = db.GetBalance("Count", nil)
	if count != 3 {
		t.Errorf("GetBalance without key wrong count: %d != %d", 3, count)
	}
	count = db.GetBalance("Count", testData10.OwnerPubKey)
	if count != 2 {
		t.Errorf("GetBalance with key wrong count: %d != %d", 2, count)
	}
	db.SetToken(*testData12)
	db.ExpireUnusable()
	tokenResult, err := db.GetToken(testData12.Hash, -1)
	if err == nil {
		t.Error("GetToken expire MUST fail")
	}
	_ = tokenResult
	db.DelToken(testData.Hash)
	db.DelToken(testData2.Hash)
	db.DelToken(testData3.Hash)
	db.DelToken(testData4.Hash)
	db.DelToken(testData5.Hash)
	db.DelToken(testData6.Hash)
	db.DelToken(testData7.Hash)
	db.DelToken(testData8.Hash)
	db.DelToken(testData9.Hash)
	db.DelToken(testData10.Hash)
	db.DelToken(testData11.Hash)
}

func TestSQLite3DB(t *testing.T) {
	dbHandle, err := sql.Open("sqlite3", sqliteDB)
	if err != nil {
		t.Fatalf("SQLiteDB Open failed: %s", err)
	}
	db, err := New(dbHandle)
	if err != nil {
		t.Fatalf("DB Create failed: %s", err)
	}
	db.DelToken(testData.Hash)
	db.DelToken(testData2.Hash)
	db.DelToken(testData3.Hash)
	db.DelToken(testData4.Hash)
	db.DelToken(testData5.Hash)
	db.DelToken(testData6.Hash)
	db.DelToken(testData7.Hash)
	db.DelToken(testData8.Hash)
	db.DelToken(testData9.Hash)
	db.DelToken(testData10.Hash)
	db.DelToken(testData11.Hash)
	err = db.SetToken(*testData)
	if err != nil {
		t.Errorf("SetToken failed: %s", err)
	}
	db.SetToken(*testData2)
	db.SetToken(*testData3)
	db.SetToken(*testData4)
	db.CleanLocks(true)
	lockID := db.LockToken(testData.Hash)
	if lockID <= 0 {
		t.Error("Lock failed")
	}
	lockID2 := db.LockToken(testData.Hash)
	if lockID2 > 0 {
		t.Error("Lock MUST fail")
	}
	db.UnlockToken(testData.Hash)
	lockID = db.LockToken(testData.Hash)
	if lockID <= 0 {
		t.Error("Unlock failed")
	}
	testDataResult, err := db.GetToken(testData.Hash, -1)
	if err != nil {
		t.Errorf("GetToken failed: %s", err)
	}
	err = compareTestData(testData, testDataResult)
	if err != nil {
		t.Errorf("%s", err)
	}
	_, err = db.GetToken(testData.Hash, 0)
	if err == nil || err != client.ErrLocked {
		t.Errorf("GetToken MUST fail with ErrLocked: %s", err)
	}
	_, err = db.GetToken(testData.Hash, lockID)
	if err != nil {
		t.Errorf("GetToken failed on locked token: %s", err)
	}
	db.UnlockToken(testData.Hash)
	testData.Expire = times.Now() + 3600*300*24
	testData.NewOwnerPubKey = nil
	err = db.SetToken(*testData)
	if err != nil {
		t.Errorf("SetToken Update failed: %s", err)
	}
	err = db.SetAuthToken([]byte("testing authtoken"), 2)
	if err != nil {
		t.Errorf("SetAuthToken failed: %s", err)
	}
	token, tries := db.GetAuthToken()
	if string(token) != "testing authtoken" || tries != 2 {
		t.Errorf("GetAuthToken failed: %s != %s || %d != %d", token, "testing authtoken", tries, 2)
	}
	verifyKey := [ed25519.PublicKeySize]byte{0x01, 0x02, 0x03}
	verifyKeys := make([][ed25519.PublicKeySize]byte, 0, 1)
	verifyKeys = append(verifyKeys, verifyKey)
	db.SetVerifyKeys(verifyKeys)
	verifyKeys = db.GetVerifyKeys()
	if verifyKeys[0] != verifyKey {
		t.Error("Set/GetVerifyKeys wrong data")
	}
	testDataResult, err = db.FindToken(testData.Usage)
	if err != nil {
		t.Errorf("FindToken failed: %s", err)
	}
	err = compareTestData(testData2, testDataResult)
	if err != nil {
		t.Errorf("%s", err)
	}
	testDataResult, err = db.GetAndLockToken(testData.Usage, testData.OwnerPubKey)
	if err != nil {
		t.Errorf("GetAndLockToken failed: %s", err)
	}
	err = compareTestData(testData3, testDataResult)
	if err != nil {
		t.Errorf("%s", err)
	}
	testDataResult, err = db.GetAndLockToken(testData.Usage, nil)
	if err != nil {
		t.Errorf("GetAndLockToken failed: %s", err)
	}
	err = compareTestData(testData4, testDataResult)
	if err != nil {
		t.Errorf("%s", err)
	}
	db.SetToken(*testData5)
	expireToken := db.GetExpire()
	if expireToken == nil {
		t.Error("Expiring token not found")
	}
	if !bytes.Equal(expireToken, testData5.Hash) {
		t.Errorf("Wrong expire-token found: %s", string(expireToken))
	}
	db.SetToken(*testData6)
	reissueToken := db.GetInReissue()
	if reissueToken == nil {
		t.Error("Reissue-Token not found")
	}
	if !bytes.Equal(reissueToken, testData6.Hash) {
		t.Errorf("Wrong reissue-token found: %s", string(reissueToken))
	}
	db.SetToken(*testData7)
	db.SetToken(*testData8)
	db.SetToken(*testData9)
	db.SetToken(*testData10)
	db.SetToken(*testData11)
	count := db.GetBalanceOwn("Count")
	if count != 2 {
		t.Errorf("GetBalanceOwn wrong count: %d != %d", 2, count)
	}
	count = db.GetBalance("Count", nil)
	if count != 3 {
		t.Errorf("GetBalance without key wrong count: %d != %d", 3, count)
	}
	count = db.GetBalance("Count", testData10.OwnerPubKey)
	if count != 2 {
		t.Errorf("GetBalance with key wrong count: %d != %d", 2, count)
	}
	db.SetToken(*testData12)
	db.ExpireUnusable()
	tokenResult, err := db.GetToken(testData12.Hash, -1)
	if err == nil {
		t.Error("GetToken expire MUST fail")
	}
	_ = tokenResult
	db.DelToken(testData.Hash)
	db.DelToken(testData2.Hash)
	db.DelToken(testData3.Hash)
	db.DelToken(testData4.Hash)
	db.DelToken(testData5.Hash)
	db.DelToken(testData6.Hash)
	db.DelToken(testData7.Hash)
	db.DelToken(testData8.Hash)
	db.DelToken(testData9.Hash)
	db.DelToken(testData10.Hash)
	db.DelToken(testData11.Hash)
	db.DB.Close()
	os.Remove(sqliteDB)
}

func TestTypes(t *testing.T) {
	global, state := encodeToken(testData)
	testDataResult, err := decodeToken(global, state)
	if err != nil {
		t.Errorf("Decode failed: %s", err)
	}
	err = compareTestData(testData, testDataResult)
	if err != nil {
		t.Errorf("%s", err)
	}
	testData.OwnerPrivKey = nil
	global, state = encodeToken(testData)
	testDataResult, err = decodeToken(global, state)
	if err != nil {
		t.Errorf("Decode failed: %s", err)
	}
	err = compareTestData(testData, testDataResult)
	if err != nil {
		t.Errorf("%s", err)
	}
	testData.NewOwnerPubKey = nil
	global, state = encodeToken(testData)
	testDataResult, err = decodeToken(global, state)
	if err != nil {
		t.Errorf("Decode failed: %s", err)
	}
	err = compareTestData(testData, testDataResult)
	if err != nil {
		t.Errorf("%s", err)
	}
	testData.NewOwnerPrivKey = nil
	global, state = encodeToken(testData)
	testDataResult, err = decodeToken(global, state)
	if err != nil {
		t.Errorf("Decode failed: %s", err)
	}
	err = compareTestData(testData, testDataResult)
	if err != nil {
		t.Errorf("%s", err)
	}
	testData.Params = nil
	global, state = encodeToken(testData)
	testDataResult, err = decodeToken(global, state)
	if err != nil {
		t.Errorf("Decode failed: %s", err)
	}
	err = compareTestData(testData, testDataResult)
	if err != nil {
		t.Errorf("%s", err)
	}
	testData.ServerPacket = nil
	global, state = encodeToken(testData)
	testDataResult, err = decodeToken(global, state)
	if err != nil {
		t.Errorf("Decode failed: %s", err)
	}
	err = compareTestData(testData, testDataResult)
	if err != nil {
		t.Errorf("%s", err)
	}
	testData.BlindingFactors = nil
	global, state = encodeToken(testData)
	if len(state) != 0 {
		t.Error("State should be nil")
	}
	testDataResult, err = decodeToken(global, state)
	if err != nil {
		t.Errorf("Decode failed: %s", err)
	}
	err = compareTestData(testData, testDataResult)
	if err != nil {
		t.Errorf("%s", err)
	}
}

func compareTestData(testData, testDataResult *client.TokenEntry) error {
	if testData.Renewable != testDataResult.Renewable {
		return fmt.Errorf("Decode failed, Renewable: %t != %t", testData.Renewable, testDataResult.Renewable)
	}
	if testData.CanReissue != testDataResult.CanReissue {
		return fmt.Errorf("Decode failed, CanReissue: %t != %t", testData.CanReissue, testDataResult.CanReissue)
	}
	if testData.Usage != testDataResult.Usage {
		return fmt.Errorf("Decode failed, Usage: %s != %s", testData.Usage, testDataResult.Usage)
	}
	if testData.Expire != testDataResult.Expire {
		return fmt.Errorf("Decode failed, Expire: %d != %d", testData.Expire, testDataResult.Expire)
	}
	if !bytes.Equal(testData.Hash, testDataResult.Hash) {
		return fmt.Errorf("Decode failed, Hash: %s != %s", testData.Hash, testDataResult.Hash)
	}
	if !bytes.Equal(testData.Token, testDataResult.Token) {
		return fmt.Errorf("Decode failed, Token: %s != %s", testData.Token, testDataResult.Token)
	}
	if testData.OwnerPubKey == nil {
		if testDataResult.OwnerPubKey != nil {
			return fmt.Errorf("Decode failed, OwnerPubKey, nil!=nil")
		}
	} else if *testData.OwnerPubKey != *testDataResult.OwnerPubKey {
		return fmt.Errorf("Decode failed, OwnerPubKey, %x!=%x", testData.OwnerPubKey, testDataResult.OwnerPubKey)
	}
	if testData.OwnerPrivKey == nil {
		if testDataResult.OwnerPrivKey != nil {
			return fmt.Errorf("Decode failed, OwnerPrivKey, nil!=nil")
		}
	} else if *testData.OwnerPrivKey != *testDataResult.OwnerPrivKey {
		return fmt.Errorf("Decode failed, OwnerPrivKey, %x!=%x", testData.OwnerPrivKey, testDataResult.OwnerPrivKey)
	}
	if testData.Params == nil {
		if testDataResult.Params != nil {
			return fmt.Errorf("Decode failed, Params, nil!=nil")
		}
	} else if !bytes.Equal(testData.Params, testDataResult.Params) {
		return fmt.Errorf("Decode failed, Params, %x!=%x", testData.Params, testDataResult.Params)
	}
	if testData.ServerPacket == nil {
		if testDataResult.ServerPacket != nil {
			return fmt.Errorf("Decode failed, ServerPacket, nil!=nil")
		}
	} else if !bytes.Equal(testData.ServerPacket, testDataResult.ServerPacket) {
		return fmt.Errorf("Decode failed, ServerPacket, %x!=%x", testData.ServerPacket, testDataResult.ServerPacket)
	}
	if testData.BlindingFactors == nil {
		if testDataResult.BlindingFactors != nil {
			return fmt.Errorf("Decode failed, BlindingFactors, nil!=nil")
		}
	} else if !bytes.Equal(testData.BlindingFactors, testDataResult.BlindingFactors) {
		return fmt.Errorf("Decode failed, BlindingFactors, %x!=%x", testData.BlindingFactors, testDataResult.BlindingFactors)
	}
	if testData.NewOwnerPubKey == nil {
		if testDataResult.NewOwnerPubKey != nil {
			return fmt.Errorf("Decode failed, NewOwnerPubKey, nil!=nil")
		}
	} else if *testData.NewOwnerPubKey != *testDataResult.NewOwnerPubKey {
		return fmt.Errorf("Decode failed, NewOwnerPubKey, %x!=%x", testData.NewOwnerPubKey, testDataResult.NewOwnerPubKey)
	}
	if testData.NewOwnerPrivKey == nil {
		if testDataResult.NewOwnerPrivKey != nil {
			return fmt.Errorf("Decode failed, NewOwnerPrivKey, nil!=nil")
		}
	} else if *testData.NewOwnerPrivKey != *testDataResult.NewOwnerPrivKey {
		return fmt.Errorf("Decode failed, NewOwnerPrivKey, %x!=%x", testData.NewOwnerPrivKey, testDataResult.NewOwnerPrivKey)
	}
	return nil
}

func TestCacheData(t *testing.T) {
	cd := CacheData{
		AuthToken:  []byte("Testing AuthToken"),
		AuthTries:  10,
		VerifyKeys: make([][ed25519.PublicKeySize]byte, 0),
	}
	cd.VerifyKeys = append(cd.VerifyKeys, [ed25519.PublicKeySize]byte{0x00, 0x01, 0x03})
	cd.VerifyKeys = append(cd.VerifyKeys, [ed25519.PublicKeySize]byte{0x00, 0x01, 0x04})
	cd.VerifyKeys = append(cd.VerifyKeys, [ed25519.PublicKeySize]byte{0x00, 0x01, 0x01})
	cd.VerifyKeys = append(cd.VerifyKeys, [ed25519.PublicKeySize]byte{0x00, 0x01, 0x02})
	data := cd.Marshal()
	cdt, err := new(CacheData).Unmarshal(data)
	if err != nil {
		t.Errorf("CacheData unmarshal failed: %s", err)
	}
	if !bytes.Equal(cd.AuthToken, cdt.AuthToken) {
		t.Errorf("Authtoken no match: %s != %s", cd.AuthToken, cdt.AuthToken)
	}
	if cd.AuthTries != cdt.AuthTries {
		t.Errorf("AuthTries no match: %d != %d", cd.AuthTries, cdt.AuthTries)
	}
	for i, k := range cdt.VerifyKeys {
		if cd.VerifyKeys[i] != k {
			t.Errorf("Key unmatch: %d", i)
		}
	}
}
