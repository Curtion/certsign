package signtool

import (
	"testing"
)

func TestMatchCertMissing(t *testing.T) {
	cases := []struct {
		tail string
		want bool
	}{
		{"SignerCert not found", true},
		{"error 0x800B010A", true},
		{"CRYPT_E_NOT_FOUND 0x80092004", true},
		{"Cannot find the specified certificate", true},
		{"some other error", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := MatchCertMissing(tc.tail); got != tc.want {
			t.Errorf("MatchCertMissing(%q) = %v, want %v", tc.tail, got, tc.want)
		}
	}
}
