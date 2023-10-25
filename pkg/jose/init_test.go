package jose_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
)

var privateKey *rsa.PrivateKey
var publicKey *rsa.PublicKey
var verifyPublicKey *rsa.PublicKey

func init() {
	// Generate sample RSA private and public keys for testing
	var err error
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	publicKey = &privateKey.PublicKey

	// Write private key to "test.pem"
	privateKeyFile, err := os.Create("test.pem")
	if err != nil {
		panic(err)
	}
	defer privateKeyFile.Close()

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		panic(err)
	}

	// Write public key to "test.pub"
	publicKeyFile, err := os.Create("test.pub")
	if err != nil {
		panic(err)
	}
	defer publicKeyFile.Close()

	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		panic(err)
	}

	publicKeyPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyDER,
	}
	if err := pem.Encode(publicKeyFile, publicKeyPEM); err != nil {
		panic(err)
	}
}
