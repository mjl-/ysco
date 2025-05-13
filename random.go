package main

import (
	cryptorand "crypto/rand"
	mathrand "math/rand/v2"
)

var secretRand = newChaCha8Rand()

func newChaCha8Rand() *mathrand.Rand {
	var seed [32]byte
	_, err := cryptorand.Read(seed[:])
	if err != nil {
		panic(err)
	}
	return mathrand.New(mathrand.NewChaCha8(seed))
}

func genrandom() string {
	var r string
	const chars = "abcdefghijklmnopqrstuwvxyzABCDEFGHIJKLMNOPQRSTUWVXYZ0123456789"
	for range 12 {
		r += string(chars[secretRand.IntN(len(chars))])
	}
	return r
}
