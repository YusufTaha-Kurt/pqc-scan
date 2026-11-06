package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
)

func main() {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sum := md5.Sum([]byte("x"))
	curve := ecdh.X25519()
	cfg := &tls.Config{
		MinVersion:       tls.VersionTLS10,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.CurveP256},
	}
	_, _, _, _, _ = key, ecKey, sum, curve, cfg
}
