package dvdcss

import "testing"

func TestCrackDiscKey(t *testing.T) {
	disc := playerKeys[3]
	hash := invertDecryptKey(0, disc, disc)
	if got := decryptKey(0, disc, hash); got != disc {
		t.Fatalf("forged hash is not self-consistent: got %v want %v", got, disc)
	}

	cracked, err := crackDiscKey(hash)
	if err != nil {
		t.Fatalf("crackDiscKey failed: %v", err)
	}
	if cracked != disc {
		t.Fatalf("got %v want %v", cracked, disc)
	}
}
