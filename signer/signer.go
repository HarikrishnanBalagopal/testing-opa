package main

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	payload := `{"idp_type":"saml", "idp_id":"delta", "idp_user_id":"sam"}`
	privateKeyPath := "secrets/privkey.der"
	publicKeyPath := "secrets/pubkey.der"
	privateKeyBytes, err := ioutil.ReadFile(privateKeyPath)
	must(err)
	publicKeyBytes, err := ioutil.ReadFile(publicKeyPath)
	must(err)
	privateKey, err := x509.ParseECPrivateKey(privateKeyBytes)
	must(err)
	signed, err := jws.Sign([]byte(payload), jwa.ES512, privateKey)
	must(err)
	fmt.Println("signed", string(signed))

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	must(err)
	verified, err := jws.Verify(signed, jwa.ES512, publicKey)
	must(err)
	fmt.Println("verified", string(verified))
}
