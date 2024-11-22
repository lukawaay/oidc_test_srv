package impl

import (
	"github.com/go-jose/go-jose/v4"
)

type Key struct {
	SigningKey
}

func newKey(signingKey *SigningKey) *Key {
	return &Key { *signingKey }
}

func (k *Key) ID() string {
	return k.id
}

func (k *Key) Algorithm() jose.SignatureAlgorithm {
	return k.algorithm
}

func (k *Key) Use() string {
	return "sig"
}

func (k *Key) Key() any {
	return &k.key.PublicKey
}
