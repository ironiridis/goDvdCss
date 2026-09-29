package dvdcss

import (
	"bytes"
	"testing"
)

func TestDecryptDiscKey(t *testing.T) {
	discKey := Key{0x10, 0x20, 0x30, 0x40, 0x50}
	playerKey := playerKeys[5]

	var raw [5 * 409]byte
	hash := invertDecryptKey(0, discKey, discKey)
	copy(raw[:5], hash[:])
	const pos = 137
	crypted := invertDecryptKey(0, playerKey, discKey)
	copy(raw[pos*5:pos*5+5], crypted[:])

	got, err := decryptDiscKey(raw[:])
	if err != nil {
		t.Fatalf("decryptDiscKey failed: %v", err)
	}
	if got != discKey {
		t.Fatalf("got %v want %v", got, discKey)
	}
}

func TestDecryptDiscKeyNoMatch(t *testing.T) {
	var raw [5 * 409]byte
	if _, err := decryptDiscKey(raw[:]); err == nil {
		t.Fatal("expected an error when no player key matches the hash")
	}
}

func TestDecryptTitleKey(t *testing.T) {
	discKey := Key{0x01, 0x02, 0x03, 0x04, 0x05}
	titleKey := Key{0xaa, 0xbb, 0xcc, 0xdd, 0xee}

	encrypted := invertDecryptKey(0xff, discKey, titleKey)
	if got := decryptTitleKey(discKey, encrypted); got != titleKey {
		t.Fatalf("got %v want %v", got, titleKey)
	}
}

func TestUnscramble(t *testing.T) {
	titleKey := Key{0x11, 0x22, 0x33, 0x44, 0x55}
	seed := [KeySize]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee}

	plain := make([]byte, BlockSize)
	for i := range plain {
		plain[i] = byte(i * 7)
	}

	sector := make([]byte, BlockSize)
	copy(sector, plain)
	copy(sector[0x54:0x59], seed[:])
	sector[0x14] = 0x20 // PES_scrambling_control: scrambled

	keystream := cssKeystream(titleKey, seed, BlockSize-0x80)
	for i, k := range keystream {
		sector[0x80+i] = invTab1[plain[0x80+i]^k]
	}

	if err := unscramble(titleKey, sector); err != nil {
		t.Fatalf("unscramble failed: %v", err)
	}
	if !bytes.Equal(sector[0x80:], plain[0x80:]) {
		t.Fatal("unscrambled payload does not match the original plaintext")
	}

	// a sector with PES_scrambling_control cleared must be left untouched.
	clear := append([]byte(nil), sector...)
	clear[0x14] = 0
	before := append([]byte(nil), clear...)
	if err := unscramble(titleKey, clear); err != nil {
		t.Fatalf("unscramble failed on an unscrambled sector: %v", err)
	}
	if !bytes.Equal(clear, before) {
		t.Fatal("unscramble modified a sector marked as not scrambled")
	}
}

func TestAttackPattern(t *testing.T) {
	titleKey := Key{0x12, 0x34, 0x56, 0x78, 0x9a}
	// a short repeating pattern spanning the search window (sector[0:0x80])
	// and continuing past 0x80, satisfying the known-plaintext assumption.
	pattern := []byte{0x10, 0x20, 0x30, 0x40}
	const known = 16
	plain := make([]byte, 0x80+known)
	for i := range plain {
		plain[i] = pattern[i%len(pattern)]
	}
	// the sector seed lives at 0x54-0x58, inside the search window, so it
	// must keep the pattern intact rather than overwrite it.
	var seed [KeySize]byte
	copy(seed[:], plain[0x54:0x59])

	sector := make([]byte, BlockSize)
	copy(sector, plain)

	keystream := cssKeystream(titleKey, seed, known)
	for i, k := range keystream {
		sector[0x80+i] = invTab1[plain[0x80+i]^k]
	}

	got, ok := attackPattern(sector)
	if !ok {
		t.Fatal("attackPattern failed to recover the title key")
	}
	if got != titleKey {
		t.Fatalf("got %v want %v", got, titleKey)
	}
}
