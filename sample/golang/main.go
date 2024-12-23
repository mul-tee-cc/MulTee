package main

import (
	b64 "encoding/base64"
	"errors"
	"fmt"
	"multee.cc/multee"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"
)

func splitURL(uri string) (string, string, error) {
	ur, e := url.Parse(uri)
	if e != nil {
		return "", "", errors.New("malformed key URL")
	}

	keyName := regexp.MustCompile(".*/([^/]+)").FindStringSubmatch(ur.Path)[1]
	if len(keyName) == 0 {
		return "", "", errors.New("malformed key URL")
	}

	pathPrefix := regexp.MustCompile("(.*/)[^/]+").FindStringSubmatch(ur.Path)[1]
	if len(pathPrefix) == 0 {
		return "", "", errors.New("malformed key URL")
	}

	ur.Path = pathPrefix
	return ur.String(), keyName, nil
}

func usage() {

	fmt.Println("Usage:")
	fmt.Println("  go-sample [test|err-aead|err-sig|err-msg] KEY-URL id-credentials.zip")
	fmt.Println("or")
	fmt.Println("  go-sample [bench|bench-dedicated-ecc] KEY-URL id-credentials.zip <threads> <cycles>")
	fmt.Println("sample:")
	fmt.Printf("  %s test file://./EccKey id-credentials.zip\n", os.Args[0])
	os.Exit(1)
}

func main() {

	if 4 == len(os.Args) {
		kh, keyName := getSharedKey(os.Args[2], os.Args[3])

		if "test" == os.Args[1] {
			if keyName == "TestKey" {
				testCBC(kh)
				testCBCExplicitIV(kh)
				testGCM(kh)
				testGCMAEAD(kh)
			} else if keyName == "HmacKey" {
				testHMAC(kh)
			} else {
				testSign(kh)
			}
		} else if "err-aead" == os.Args[1] {
			testCorruptAEAD(kh)
		} else if "err-sig" == os.Args[1] {
			testCorruptSig(kh)
		} else if "err-msg" == os.Args[1] {
			testCorruptMsg(kh)
		} else {
			usage()
		}
	} else if 6 == len(os.Args) {
		threads, _ := strconv.Atoi(os.Args[4])
		rounds, _ := strconv.Atoi(os.Args[5])
		if "bench" == os.Args[1] {
			kh, keyName := getSharedKey(os.Args[2], os.Args[3])

			if keyName == "TestKey" {
				benchCBC(kh, threads, int64(rounds))
			} else if keyName == "HmacKey" {
				benchHMAC(kh, threads, int64(rounds))
			} else {
				benchSign(kh, threads, int64(rounds))
			}
		} else if "bench-dedicated-ecc" == os.Args[1] {
			mkKey := func() *multee.SigningKey {
				return getDedicatedKey("file://./", "EccKey", os.Args[3])
			}
			benchDedicatedEcc(mkKey, threads, int64(rounds))
		} else {
			usage()
		}
	} else {
		usage()
	}
}

func testCBC(kh multee.KeyHandle) {
	key, _ := kh.Symmetric()

	testMsg := "cbcRandomIV"
	var plaintext = []byte(testMsg)

	ciphertext, iv, e := key.EncryptCBC(plaintext)
	if e != nil {
		fmt.Printf("  %s\n", e.Error())
		return
	}

	fmt.Println("CBC")
	fmt.Printf("  Message: %s\n", testMsg)
	fmt.Printf("  Encrypted: %s\n", b64.StdEncoding.EncodeToString(ciphertext))
	fmt.Printf("  IV: %s\n", b64.StdEncoding.EncodeToString(iv))

	dec, e := key.DecryptCBC(ciphertext, iv)
	if e != nil {
		fmt.Printf("  %s\n", e.Error())
	} else {
		fmt.Printf("  Decrypted: %s\n", string(dec))
		fmt.Printf("  Tested Ok: true\n")
	}

}

func testCBCExplicitIV(kh multee.KeyHandle) {
	key, _ := kh.Symmetric()

	testMsg := "cbcExplicitIV"
	var plaintext = []byte(testMsg)
	var ivIn = new([16]byte)

	ciphertext, iv, e := key.EncryptCBC(plaintext, ivIn[:])
	if e != nil {
		fmt.Printf("  %s\n", e.Error())
		return
	}

	fmt.Println("CBC explicit IV")
	fmt.Printf("  Message: %s\n", testMsg)
	fmt.Printf("  Encrypted: %s\n", b64.StdEncoding.EncodeToString(ciphertext))
	fmt.Printf("  IV: %s\n", b64.StdEncoding.EncodeToString(iv))

	dec, e := key.DecryptCBC(ciphertext, iv)
	if e != nil {
		fmt.Printf("  %s\n", e.Error())
	} else {
		fmt.Printf("  Decrypted: %s\n", string(dec))
		fmt.Printf("  Tested Ok: true\n")
	}
}

func testHMAC(kh multee.KeyHandle) {
	key, _ := kh.Hmac()

	testMsg := "testMsg"
	var plaintext = []byte(testMsg)

	res, e := key.HmacSHA256(plaintext)
	if e != nil {
		fmt.Printf("  %s\n", e.Error())
	} else {
		fmt.Println("HMAC")
		fmt.Printf("  Message: %s\n", testMsg)
		fmt.Printf("  hmac256: %s\n", b64.StdEncoding.EncodeToString(res))
		fmt.Printf("  Tested Ok: true\n")
	}
}

func testSign(kh multee.KeyHandle) {
	key, _ := kh.Signing()

	testMsg := "testMsg"
	var plaintext = []byte(testMsg)

	res, e := key.Sign(plaintext)
	if e != nil {
		fmt.Printf("  %s\n", e.Error())
		return
	}

	fmt.Println("Sign")
	fmt.Printf("  Message: %s\n", testMsg)
	fmt.Printf("  Signature: %s\n", b64.StdEncoding.EncodeToString(res))

	pub := key.GetPublicKey()
	ok, _ := pub.Verify(plaintext, res)

	fmt.Printf("  Verify: %t\n", ok)
	fmt.Printf("  Tested Ok: %t\n", ok)
}

func testGCM(kh multee.KeyHandle) {
	key, _ := kh.Symmetric()

	testMsg := "GCMwithoutAAD"
	var plaintext = []byte(testMsg)

	ciphertext, iv, tag, e := key.Seal(plaintext)
	if e != nil {
		fmt.Printf("  %s\n", e.Error())
		return
	}

	fmt.Println("GCM")
	fmt.Printf("  Message: %s\n", testMsg)
	fmt.Printf("  Encrypted: %s\n", b64.StdEncoding.EncodeToString(ciphertext))
	fmt.Printf("  IV: %s\n", b64.StdEncoding.EncodeToString(iv))
	fmt.Printf("  Tag: %s\n", b64.StdEncoding.EncodeToString(tag))

	dec, e := key.Unseal(ciphertext, iv, tag)
	if e != nil {
		fmt.Printf("  %s\n", e.Error())
	} else {
		fmt.Printf("  Decrypted: %s\n", string(dec))
		fmt.Printf("  Tested Ok: true\n")
	}

}

func testCorruptAEAD(kh multee.KeyHandle) {
	key, _ := kh.Symmetric()

	testMsg := "testMsg"
	var plaintext = []byte(testMsg)

	ciphertext, iv, tag, _ := key.Seal(plaintext)

	fmt.Println("GCM(corrupted)")
	fmt.Printf("  Message: %s\n", testMsg)
	fmt.Printf("  Encrypted: %s\n", b64.StdEncoding.EncodeToString(ciphertext))
	fmt.Println()

	fmt.Println("..corrupting..")
	var corrupted = ciphertext
	corrupted[0] = corrupted[0] ^ 1
	fmt.Println()

	fmt.Println("..decrypting..")
	dec, e := key.Unseal(corrupted, iv, tag)
	if e == nil {
		fmt.Printf("  Decrypted: %s\n", string(dec))
		fmt.Printf("  IV: %s\n", b64.StdEncoding.EncodeToString(iv))
		fmt.Printf("  Tag: %s\n", b64.StdEncoding.EncodeToString(tag))
	} else {
		fmt.Printf("  Error:  %s\n", e.Error())

		dcErr, _ := e.(*multee.MulTeeError)
		fmt.Printf("  Is tag verification error: %t\n", dcErr.ErrorCode == multee.ERR_CRYPTO_AUTH_TAG_VERIFY_FAILED)
		fmt.Printf("  Tested Ok: true\n")
	}

}

func testGCMAEAD(kh multee.KeyHandle) {
	key, _ := kh.Symmetric()

	testMsg := "GCMwithAAD"
	var plaintext = []byte(testMsg)
	aad := "AAD"
	var aadBytes = []byte(aad)

	ciphertext, iv, tag, _ := key.Seal(plaintext, aadBytes)

	fmt.Println("GCM with AAD")
	fmt.Printf("  Message: %s\n", testMsg)
	fmt.Printf("  AAD: %s\n", aad)
	fmt.Printf("  Encrypted: %s\n", b64.StdEncoding.EncodeToString(ciphertext))
	fmt.Printf("  IV: %s\n", b64.StdEncoding.EncodeToString(iv))
	fmt.Printf("  Tag: %s\n", b64.StdEncoding.EncodeToString(tag))

	dec, e := key.Unseal(ciphertext, iv, tag, aadBytes)
	if e != nil {
		fmt.Printf("  %s\n", e.Error())
	} else {
		fmt.Printf("  Decrypted: %s\n", string(dec))
		fmt.Printf("  Tested Ok: true\n")
	}

}

func testCorruptSig(kh multee.KeyHandle) {
	key, _ := kh.Signing()

	testMsg := "testMsg"
	var plaintext = []byte(testMsg)

	res, _ := key.Sign(plaintext)
	fmt.Println("..corrupting signature..")
	var corrupted = make([]byte, len(res))
	copy(corrupted, res)
	corrupted[0] = corrupted[0] ^ 1
	fmt.Println()

	fmt.Println("..verifying..")
	pub := key.GetPublicKey()
	ok, er := pub.Verify(plaintext, corrupted)

	fmt.Println("Sign")
	fmt.Printf("  Message: %s\n", testMsg)
	fmt.Printf("  Signature: %s\n", b64.StdEncoding.EncodeToString(res))
	fmt.Printf("  Corrupt signature: %s\n", b64.StdEncoding.EncodeToString(corrupted))
	fmt.Printf("  Verify: %t\n", ok)
	fmt.Printf("  Verify err: %s\n", er)
	//var multeeError *multee.MulTeeError
	//if errors.As(er, &multee) {
	//	fmt.Printf("  Is ERR_CRYPTO_AUTH_TAG_VERIFY_FAILED error: %t\n", multee.ErrorCode == multee.ERR_CRYPTO_AUTH_TAG_VERIFY_FAILED)
	//}
}

func testCorruptMsg(kh multee.KeyHandle) {
	key, _ := kh.Signing()

	testMsg := "testMsg"
	var plaintext = []byte(testMsg)

	res, _ := key.Sign(plaintext)
	fmt.Println("..corrupting message..")
	var corrupted = make([]byte, len(plaintext))
	copy(corrupted, plaintext)
	corrupted[0] = corrupted[0] ^ 1
	fmt.Println()

	fmt.Println("..verifying..")
	pub := key.GetPublicKey()
	ok, er := pub.Verify(corrupted, res)

	fmt.Println("Sign")
	fmt.Printf("  Message: %s\n", testMsg)
	fmt.Printf("  Signature: %s\n", b64.StdEncoding.EncodeToString(res))
	fmt.Printf("  Corrupt message: %s\n", b64.StdEncoding.EncodeToString(corrupted))
	fmt.Printf("  Verify: %t\n", ok)
	fmt.Printf("  Verify err: %s\n", er)
}

func benchHMAC(kh multee.KeyHandle, threads int, cycles int64) {
	key, _ := kh.Hmac()

	testMsg := "testMsg"
	var plaintext = []byte(testMsg)

	f := func() error {
		_, e := key.HmacSHA256(plaintext)
		return e
	}

	fmt.Println("HMAC SHA256 7 bytes")
	bench(f, threads, cycles)
}

func benchSign(kh multee.KeyHandle, threads int, cycles int64) {
	key, _ := kh.Signing()

	testMsg := "testMsg"
	var plaintext = []byte(testMsg)

	f := func() error {
		_, e := key.Sign(plaintext)
		return e
	}

	fmt.Println("Sign 7 bytes")
	bench(f, threads, cycles)
}

func benchCBC(kh multee.KeyHandle, threads int, cycles int64) {
	key, _ := kh.Symmetric()

	testMsg := "testMsg"
	var plaintext = []byte(testMsg)
	var iv_in = new([16]byte)

	f := func() error {
		_, _, e := key.EncryptCBC(plaintext, iv_in[:])
		return e
	}

	fmt.Println("AES256 CBC with Padding 7 bytes")
	bench(f, threads, cycles)
}

func bench(f func() error, threads int, cycles int64) {

	start := time.Now().UnixNano()
	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < int(cycles); j++ {
				e := f()
				if e != nil {
					fmt.Printf("err  %s\n", e.Error())
					break
				}
			}
		}()
	}

	wg.Wait()
	end := time.Now().UnixNano()

	fmt.Println("Rounds: ", cycles)
	fmt.Println("Runtime (ms): ", (end-start)/1000000.0)
	fmt.Println("op/s: ", cycles*1000000000/(end-start))
	fmt.Println("throughput/s: ", cycles*1000000000/(end-start)*int64(threads))
}

func benchDedicatedEcc(f func() *multee.SigningKey, threads int, cycles int64) {

	start := time.Now().UnixNano()
	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		key := f()
		testMsg := "testMsg"
		var plaintext = []byte(testMsg)

		go func() {
			defer wg.Done()
			for j := 0; j < int(cycles); j++ {
				key.Sign(plaintext)
			}
		}()
	}

	wg.Wait()
	end := time.Now().UnixNano()

	fmt.Println("Rounds: ", cycles)
	fmt.Println("Runtime (ms): ", (end-start)/1000000.0)
	fmt.Println("op/s: ", cycles*1000000000/(end-start))
	fmt.Println("throughput/s: ", cycles*1000000000/(end-start)*int64(threads))
}

func getDedicatedKey(uriPrefix string, keyName string, creds string) *multee.SigningKey {

	dc, e := multee.NewMulTee(uriPrefix, []string{keyName}, creds)
	if e != nil {
		os.Exit(1)
	}
	kh, e := dc.GetKey(keyName)
	if e != nil {
		os.Exit(1)
	}
	k, e := kh.Signing()
	if e != nil {
		os.Exit(1)
	}
	return &k
}

func getSharedKey(url string, creds string) (multee.KeyHandle, string) {

	uriPrefix, keyName, e := splitURL(url)
	if e != nil {
		fmt.Println("Malformed key URL")
		fmt.Println(e.Error())
		os.Exit(1)
	}

	dc, e := multee.NewMulTee(uriPrefix, []string{keyName}, creds)
	if e != nil {
		fmt.Println(e.Error())
		os.Exit(1)
	}

	kh, e := dc.GetKey(keyName)
	if e != nil {
		fmt.Printf("  Error:  %s\n", e.Error())
		os.Exit(1)
	}

	return kh, keyName
}
