package crypto_ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
)

var curve = elliptic.P256()

func NewKeyPair() ([]byte, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		fmt.Println(err)
		return []byte{}, []byte{}, err
	}

	pubkey := append(privateKey.X.Bytes(), privateKey.Y.Bytes()...)
	privkey := privateKey.D.Bytes()

	return pubkey, privkey, nil
}

func Sign(publicKey []byte, privateKey []byte, data []byte) ([]byte, error) {
	privkey := ecdsa.PrivateKey{}
	privkey.Curve = curve
	privkey.X, privkey.Y, privkey.D = big.NewInt(0), big.NewInt(0), big.NewInt(0)

	privkey.X.SetBytes(publicKey[:])
	privkey.Y.SetBytes(publicKey[:])
	privkey.D.SetBytes(privateKey[:])

	r, s, err := ecdsa.Sign(rand.Reader, &privkey, data)
	if err != nil {
		return []byte{}, err
	}

	encoded := append(r.Bytes(), s.Bytes()...)
	return encoded, nil
}

func Verify(publicKey []byte, data []byte, encodedData []byte) bool {
	pubkey := ecdsa.PublicKey{Curve: curve, X: big.NewInt(0), Y: big.NewInt(0)}
	pubkey.X.SetBytes(publicKey[:len(publicKey)/2])
	pubkey.Y.SetBytes(publicKey[len(publicKey)/2:])

	r, s := big.NewInt(0), big.NewInt(0)
	r.SetBytes(encodedData[:len(encodedData)/2])
	s.SetBytes(encodedData[len(encodedData)/2:])

	return ecdsa.Verify(&pubkey, data, r, s)
}
