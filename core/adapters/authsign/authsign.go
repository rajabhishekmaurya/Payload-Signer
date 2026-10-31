package authsign

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"payload-signer/constant"
	"payload-signer/core/ports"
	"strconv"
	"strings"
	"time"
)

type signer struct {
	signatureAlgorithm, digestAlgorithm string
}

func NewSignerAdapter() ports.ISigner {
	return &signer{
		signatureAlgorithm: constant.SIGNATURE_ALGORITHM,
		digestAlgorithm:    constant.DIGEST_ALGORITHM,
	}
}

// Load implements ports.ISigner.
func (s *signer) Load(isVerify bool, privateKey string, publicKey string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	if isVerify {
		pubBlock, _ := pem.Decode([]byte(publicKey))
		if pubBlock == nil {
			return nil, nil, errors.New("failed to decode public key")
		}

		parsedPublicKey, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse public key: %w", err)
		}

		rsaPublicKey, ok := parsedPublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, nil, errors.New("parsed public key is not an RSA public key")
		}

		return nil, rsaPublicKey, nil
	}

	privBlock, _ := pem.Decode([]byte(privateKey))
	if privBlock == nil {
		return nil, nil, errors.New("failed to decode private key")
	}
	parsedPrivateKey, err := x509.ParsePKCS1PrivateKey(privBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return parsedPrivateKey, nil, nil
}

// Sign implements ports.ISigner.
func (s *signer) Sign(privateKey *rsa.PrivateKey, data string, ttl time.Duration) (string, error) {
	var expiryTime int64
	if ttl > 0 {
		expiryTime = time.Now().Add(ttl).UnixMilli()
		data = fmt.Sprintf("%d:%s", expiryTime, data)
	}

	hash := sha256.Sum256([]byte(data))
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hash[:], nil)
	if err != nil {
		return "", err
	}
	if expiryTime != 0 {
		return fmt.Sprintf("%d:%s", expiryTime, base64.StdEncoding.EncodeToString(signature)), nil
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

// Verify implements ports.ISigner.
func (s *signer) Verify(publicKey *rsa.PublicKey, data string, signature string) error {
	var expiryTime string
	signatureArr := strings.Split(signature, ":")
	if len(signatureArr) == 2 {
		expiryTime = signatureArr[0]
		signature = signatureArr[1]
		data = fmt.Sprintf("%s:%s", expiryTime, data)
	}

	if expiryTime != "" {
		expiry, err := strconv.ParseInt(expiryTime, 10, 64)
		if err != nil || time.Now().UnixMilli() > expiry {
			return errors.New("signature expired")
		}
	}

	hash := sha256.Sum256([]byte(data))
	decodedSignature, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	if err := rsa.VerifyPSS(publicKey, crypto.SHA256, hash[:], decodedSignature, nil); err != nil {
		return err
	}

	return nil
}
