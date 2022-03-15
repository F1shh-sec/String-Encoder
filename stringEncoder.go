package main

import (
	"encoding/base64"
	"fmt"
	"math/big"
)

var KEY = new(big.Int).SetBytes([]byte("*S"))

func main() {
	Somestring := "Hello My name is F1shh"
	fmt.Println("Origional: " + Somestring)
	encoded := customEncode(Somestring)
	fmt.Print("Encoded String: " + encoded)
	decoded := customDecode(encoded)
	fmt.Print("Decoded String: " + decoded)
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
	if len(KEY.Bytes()) > len(bigint.Bytes()) {

		// Creates a new key of the first few bits of the key
		NewKey := new(big.Int).SetBytes(keyByteArr[:len(bytetext)])
		xorString := new(big.Int).Xor(bigint, NewKey)
		encode := b64_encode(string(xorString.Bytes()))
		return encode
	} else {
		howMuchBigger := len(bytetext) / len(keyByteArr)
		if howMuchBigger < 2 {
			missingbytes := len(bytetext) - len(keyByteArr)
			NewKey := new(big.Int).SetBytes(keyByteArr[:missingbytes])
			final := append(keyByteArr, NewKey.Bytes()...)
			finalKey := new(big.Int).SetBytes(final)
			xorString := new(big.Int).Xor(bigint, finalKey)
			encode := b64_encode(string(xorString.Bytes()))
			return encode
		} else {
			extendedkey := new(big.Int)
			newKeyArray := keyByteArr
			fmt.Println(howMuchBigger)
			for i := 1; i < howMuchBigger; i++ {
				newKeyArray = append(newKeyArray, keyByteArr...)
				if i == howMuchBigger-1 {
					extendedkey.SetBytes(newKeyArray)
				}
			}

			missingbytes := len(bytetext) - len(extendedkey.Bytes())
			NewKey := new(big.Int).SetBytes(keyByteArr[:missingbytes])
			final := append(extendedkey.Bytes(), NewKey.Bytes()...)
			finalKey := new(big.Int).SetBytes(final)
			xorString := new(big.Int).Xor(bigint, finalKey)
			encode := b64_encode(string(xorString.Bytes()))
			return encode
		}
	}
	return "hello"
}

func customDecode(text string) string {
	decode := b64_decode(text)
	decodedStr := []byte(decode)
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
			final := append(keyByteArr, NewKey.Bytes()...)
			finalKey := new(big.Int).SetBytes(final)
			xorString := new(big.Int).Xor(decodeBigInt, finalKey)
			return string(xorString.Bytes())
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
			final := append(extendedkey.Bytes(), NewKey.Bytes()...)
			finalKey := new(big.Int).SetBytes(final)
			xorString := new(big.Int).Xor(decodeBigInt, finalKey)
			return string(xorString.Bytes())
		}
	}
	return "hello"

}
