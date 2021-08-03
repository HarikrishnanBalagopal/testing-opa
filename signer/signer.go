package main

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cast"
	"github.com/spf13/cobra"
)

type Flags struct {
	Silent         bool
	UserID         string
	ExpirySeconds  int64
	PrivateKeyPath string
	PublicKeyPath  string
}

func must(err error) {
	if err != nil {
		logrus.Fatal(err)
	}
}

func handler(flags Flags) {
	now := time.Now().Unix()
	if flags.Silent {
		logrus.SetLevel(logrus.WarnLevel)
	}
	logrus.Info("the time is", now)
	logrus.Info("generating JWT access token for user:", flags.UserID)
	logrus.Info("the access token will expire in", flags.ExpirySeconds, "seconds")
	tokenData := map[string]string{
		"iss":         "somebody",
		"aud":         "m2k-api-server",
		"idp_type":    "saml",
		"idp_id":      "delta",
		"exp":         cast.ToString(now + flags.ExpirySeconds),
		"idp_user_id": flags.UserID,
	}
	payload, err := json.Marshal(tokenData)
	must(err)
	privateKeyPath := filepath.Clean(flags.PrivateKeyPath)
	publicKeyPath := filepath.Clean(flags.PublicKeyPath)
	privateKeyBytes, err := ioutil.ReadFile(privateKeyPath)
	must(err)
	publicKeyBytes, err := ioutil.ReadFile(publicKeyPath)
	must(err)

	// sign
	privateKey, err := x509.ParseECPrivateKey(privateKeyBytes)
	must(err)
	accessToken, err := jws.Sign(payload, jwa.ES512, privateKey)
	must(err)
	logrus.Info("access token ", string(accessToken))
	if flags.Silent {
		fmt.Printf("%s", accessToken)
	}

	// verify
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	must(err)
	verifiedToken, err := jws.Verify(accessToken, jwa.ES512, publicKey)
	must(err)
	logrus.Info("verified ", string(verifiedToken))
}

func main() {
	flags := Flags{}
	rootCmd := &cobra.Command{
		Use:   "signer",
		Short: "used to generate JWT access tokens",
		Run:   func(cmd *cobra.Command, args []string) { handler(flags) },
	}
	rootCmd.Flags().StringVarP(&flags.UserID, "user", "u", "", "user id to generate the token for")
	rootCmd.Flags().StringVarP(&flags.PrivateKeyPath, "privkey", "k", "secrets/privkey.der", "path to DER encoded private key file to use for signing")
	rootCmd.Flags().StringVarP(&flags.PublicKeyPath, "pubkey", "p", "secrets/pubkey.der", "path to DER encoded public key file to use for verification after signing")
	rootCmd.Flags().Int64VarP(&flags.ExpirySeconds, "expire", "e", 10*60, "number of seconds for which the token will be valid")
	rootCmd.Flags().BoolVarP(&flags.Silent, "silent", "s", false, "if true we will only print the token when there are no errors")
	must(rootCmd.MarkFlagRequired("user"))
	if err := rootCmd.Execute(); err != nil {
		logrus.Fatal(err)
		return
	}
}
