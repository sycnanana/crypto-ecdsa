package crypto_ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
)

var curve = elliptic.P256()

func NewKeyPair() ([64]byte, [32]byte, error) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		fmt.Println(err)
		return [64]byte{}, [32]byte{}, err
	}

	var pubkey [64]byte
	var privkey [32]byte
	copy(pubkey[:32], privateKey.X.Bytes())
	copy(pubkey[32:], privateKey.Y.Bytes())
	copy(privkey[:], privateKey.D.Bytes())

	return pubkey, privkey, nil
}

func Sign(publicKey [64]byte, privateKey [32]byte, data []byte) ([64]byte, error) {
	privkey := ecdsa.PrivateKey{}
	privkey.Curve = curve
	privkey.X, privkey.Y, privkey.D = big.NewInt(0), big.NewInt(0), big.NewInt(0)

	privkey.X.SetBytes(publicKey[:])
	privkey.Y.SetBytes(publicKey[:])
	privkey.D.SetBytes(privateKey[:])

	r, s, err := ecdsa.Sign(rand.Reader, &privkey, data)
	if err != nil {
		return [64]byte{}, err
	}

	var encoded [64]byte
	copy(encoded[:32], r.Bytes())
	copy(encoded[32:], s.Bytes())
	return encoded, nil
}

func Verify(publicKey [64]byte, data []byte, encodedData [64]byte) bool {
	pubkey := ecdsa.PublicKey{Curve: curve, X: big.NewInt(0), Y: big.NewInt(0)}
	pubkey.X.SetBytes(publicKey[:32])
	pubkey.Y.SetBytes(publicKey[32:])

	r, s := big.NewInt(0), big.NewInt(0)
	r.SetBytes(encodedData[:32])
	s.SetBytes(encodedData[32:])

	return ecdsa.Verify(&pubkey, data, r, s)
}
