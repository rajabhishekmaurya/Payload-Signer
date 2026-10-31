package payloadsigner

import (
	"fmt"
	"payload-signer/core/adapters/authsign"
	"payload-signer/core/ports"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_NewSigner(t *testing.T) {
	type input struct{}
	type output struct {
		signer ports.ISigner
	}

	type test struct {
		number         int
		name           string
		input          input
		expectedOutput output
	}

	testCases := []test{}

	testCases = append(testCases, test{
		number: 1,
		name: "Default scenario",
		expectedOutput: output{
			signer: authsign.NewSignerAdapter(),
		},
	})

	for _, testCase := range testCases {
		actualSigner := NewSigner()
		if !assert.Equal(t, testCase.expectedOutput.signer, actualSigner){
			fmt.Printf("testCase.number: %v\n", testCase.number)
		}
	}
}
