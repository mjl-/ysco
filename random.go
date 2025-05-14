package main

import (
	mathrand "math/rand/v2"
)

// todo: replace with crypto/rand.Text once we have go1.25
func genrandom() string {
	var r string
	const chars = "abcdefghijklmnopqrstuwvxyzABCDEFGHIJKLMNOPQRSTUWVXYZ0123456789"
	for range 12 {
		r += string(chars[mathrand.IntN(len(chars))])
	}
	return r
}
