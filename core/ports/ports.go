package ports

import (
	"crypto/rsa"
	"time"
)

type ISigner interface {
	Load(isVerify bool, privateKey string, publicKey string) (*rsa.PrivateKey, *rsa.PublicKey, error)
	Sign(privateKey *rsa.PrivateKey, data string, ttl time.Duration) (string, error)
	Verify(publicKey *rsa.PublicKey, data string, signature string) error
}
