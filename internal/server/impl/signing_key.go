package impl

import (
	"crypto/rsa"

	"github.com/go-jose/go-jose/v4"
)

type SigningKey struct {
	id string
	algorithm jose.SignatureAlgorithm
	key *rsa.PrivateKey
}

func (s *SigningKey) SignatureAlgorithm() jose.SignatureAlgorithm {
	return s.algorithm
}

func (s *SigningKey) Key() any {
	return s.key
}

func (s *SigningKey) ID() string {
	return s.id
}
