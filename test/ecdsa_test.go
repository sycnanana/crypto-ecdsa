package crypto_ecdsa

import (
	"encoding/base64"
	"testing"

	"github.com/sycnanana/crypto-ecdsa"
)

func TestEcdsa(t *testing.T) {

	pubkey, privkey, _ := crypto_ecdsa.NewKeyPair()
	t.Log("pubkey:  ", base64.StdEncoding.EncodeToString(pubkey[:]))
	t.Log("privkey: ", base64.StdEncoding.EncodeToString(privkey[:]))

	data := []byte("hello, world!")

	sig, _ := crypto_ecdsa.Sign(pubkey, privkey, data)
	t.Log("sig:  ", base64.StdEncoding.EncodeToString(sig[:]))

	t.Log("verify1: ", crypto_ecdsa.Verify(pubkey, data, sig))

	data_err := []byte("hello.world!")
	t.Log("verify2: ", crypto_ecdsa.Verify(pubkey, data_err, sig))

	pubkey[12] = pubkey[12] + 1
	t.Log("verify3: ", crypto_ecdsa.Verify(pubkey, data, sig))
}
