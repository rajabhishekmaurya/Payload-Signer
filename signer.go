package payloadsigner

import (
	"payload-signer/core/adapters/authsign"
	"payload-signer/core/ports"
)

func NewSigner() ports.ISigner {
	signerHandler := authsign.NewSignerAdapter()
	return signerHandler
}
