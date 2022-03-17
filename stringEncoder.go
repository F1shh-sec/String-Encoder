package main

import (
	"encoding/base64"
	"fmt"
	"math/big"
)

var KEY = new(big.Int).SetBytes([]byte("*SomeSuperLingComplexString"))

func main() {
	Somestring := "Hello My name is F1shh"
	fmt.Println("Origional: " + Somestring)
	encoded := customEncode(Somestring)
	fmt.Println("Encoded String: " + encoded)
	decoded := customDecode(encoded)
	fmt.Println("Decoded String: " + decoded)
}

/**
Base 64 encode a message to be sent to the server
*/
func b64_encode(text string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(text))
	return encoded
}

/**
base 64 decode a message from the server
*/
func b64_decode(text string) string {
	decoded, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		fmt.Println(err)
	}
	return string(decoded)
}

func customEncode(text string) string {
	bytetext := []byte(text)
	bigint := new(big.Int).SetBytes(bytetext)

	keyByteArr := KEY.Bytes()
	// If we need to shorten the Key
	if len(KEY.Bytes()) > len(bigint.Bytes()) {
		// Creates a new key of the first few bits of the key
		NewKey := new(big.Int).SetBytes(keyByteArr[:len(bytetext)])
		xorString := new(big.Int).Xor(bigint, NewKey)
		encode := b64_encode(string(xorString.Bytes()))
		return encode
	} else {
		// If we need to lengthen the key
		howMuchBigger := len(bytetext) / len(keyByteArr)
		if howMuchBigger < 2 {
			// If we only need to lengthen it a little bit
			missingbytes := len(bytetext) - len(keyByteArr)
			NewKey := new(big.Int).SetBytes(keyByteArr[:missingbytes])
			finalKey := new(big.Int).SetBytes(append(keyByteArr, NewKey.Bytes()...))
			encode := b64_encode(string(new(big.Int).Xor(bigint, finalKey).Bytes()))
			return encode
		} else {
			// Extends the key by a factor greater then 2
			extendedkey := new(big.Int)
			newKeyArray := keyByteArr
			// Extends key
			for i := 1; i < howMuchBigger; i++ {
				newKeyArray = append(newKeyArray, keyByteArr...)
				if i == howMuchBigger-1 {
					extendedkey.SetBytes(newKeyArray)
				}
			}
			// Calculates remaining difference
			missingbytes := len(bytetext) - len(extendedkey.Bytes())
			NewKey := new(big.Int).SetBytes(keyByteArr[:missingbytes])
			// Xor encodes
			finalKey := new(big.Int).SetBytes(append(extendedkey.Bytes(), NewKey.Bytes()...))
			encode := b64_encode(string(new(big.Int).Xor(bigint, finalKey).Bytes()))
			return encode
		}
	}
	return "hello"
}
func customDecode(text string) string {
	//Reverses order of b64 encode from Custom Encode function
	decodedStr := []byte(b64_decode(text))
	decodeBigInt := new(big.Int).SetBytes(decodedStr)

	keyByteArr := KEY.Bytes()
	if len(KEY.Bytes()) > len(decodeBigInt.Bytes()) {
		// Creates a new key of the first few bits of the key
		NewKey := new(big.Int).SetBytes(keyByteArr[:len(decodedStr)])
		xorString := new(big.Int).Xor(decodeBigInt, NewKey)
		return string(xorString.Bytes())
	} else {
		howMuchBigger := len(decodedStr) / len(keyByteArr)
		if howMuchBigger < 2 {
			missingbytes := len(decodedStr) - len(keyByteArr)
			NewKey := new(big.Int).SetBytes(keyByteArr[:missingbytes])
			finalKey := new(big.Int).SetBytes(append(keyByteArr, NewKey.Bytes()...))
			return string(new(big.Int).Xor(decodeBigInt, finalKey).Bytes())
		} else {
			extendedkey := new(big.Int)
			newKeyArray := keyByteArr
			for i := 1; i <= howMuchBigger; i++ {
				newKeyArray = append(newKeyArray, keyByteArr...)
				if i == howMuchBigger-1 {
					extendedkey.SetBytes(newKeyArray)
				}
			}
			missingbytes := len(decodedStr) - len(extendedkey.Bytes())
			NewKey := new(big.Int).SetBytes(keyByteArr[:missingbytes])
			finalKey := new(big.Int).SetBytes(append(extendedkey.Bytes(), NewKey.Bytes()...))
			return string(new(big.Int).Xor(decodeBigInt, finalKey).Bytes())
		}
	}
	return "hello"

}
