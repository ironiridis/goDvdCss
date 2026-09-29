package dvdcss

// invTab1 maps y to x such that cssTab1[x] == y, since cssTab1 is a fixed
// byte permutation.
var invTab1 = func() [256]byte {
	var inv [256]byte
	for i := range 256 {
		inv[cssTab1[i]] = byte(i)
	}
	return inv
}()

// invertDecryptKey finds the crypted block that decryptKey(invert, key, ·)
// maps to target, by inverting decryptKey's two-pass chain. Used to forge
// test fixtures without a real DVD authoring/encryption implementation.
func invertDecryptKey(invert byte, key Key, target Key) Key {
	lfsr1lo := uint32(key[0]) | 0x100
	lfsr1hi := uint32(key[1])
	lfsr0 := (uint32(key[4])<<17 | uint32(key[3])<<9 | uint32(key[2])<<1) + 8 - uint32(key[2]&7)
	lfsr0 = uint32(bitReverse(byte(lfsr0)))<<24 | uint32(bitReverse(byte(lfsr0>>8)))<<16 | uint32(bitReverse(byte(lfsr0>>16)))<<8 | uint32(bitReverse(byte(lfsr0>>24)))
	combined := uint32(0)
	var stream Key
	for i := range KeySize {
		out1 := uint32(cssTab2[byte(lfsr1hi)]) ^ uint32(cssTab3[lfsr1lo])
		lfsr1hi = lfsr1lo >> 1
		lfsr1lo = ((lfsr1lo & 1) << 8) ^ out1
		out1 = uint32(cssTab4[byte(out1)])
		out0 := uint32(byte((((((lfsr0>>8)^lfsr0)>>1)^lfsr0)>>3 ^ lfsr0) >> 7))
		lfsr0 = lfsr0>>8 | out0<<24
		combined += (out0 ^ uint32(invert)) + out1
		stream[i] = byte(combined)
		combined >>= 8
	}

	r := target
	var m Key
	m[0] = invTab1[r[0]^stream[0]]
	m[1] = invTab1[r[1]^stream[1]^m[0]]
	m[2] = invTab1[r[2]^stream[2]^m[1]]
	m[3] = invTab1[r[3]^stream[3]^m[2]]
	m[4] = invTab1[r[4]^stream[4]^m[3]]

	var c Key
	c[0] = invTab1[m[0]^stream[0]^m[4]]
	c[1] = invTab1[m[1]^stream[1]^c[0]]
	c[2] = invTab1[m[2]^stream[2]^c[1]]
	c[3] = invTab1[m[3]^stream[3]^c[2]]
	c[4] = invTab1[m[4]^stream[4]^c[3]]
	return c
}

// cssKeystream reproduces unscramble's per-byte keystream for key/seed,
// independent of any sector contents, so tests can encrypt fixtures.
func cssKeystream(key Key, seed [KeySize]byte, count int) []byte {
	t1 := uint32(key[0]^seed[0]) | 0x100
	t2 := uint32(key[1] ^ seed[1])
	t3 := (uint32(key[2]) | uint32(key[3])<<8 | uint32(key[4])<<16) ^ (uint32(seed[2]) | uint32(seed[3])<<8 | uint32(seed[4])<<16)
	t3 = t3*2 + 8 - (t3 & 7)
	t5 := uint32(0)
	out := make([]byte, count)
	for i := range count {
		t4 := uint32(cssTab2[byte(t2)]) ^ uint32(cssTab3[t1])
		t2 = t1 >> 1
		t1 = ((t1 & 1) << 8) ^ t4
		t4 = uint32(cssTab5[byte(t4)])
		feedback := (((t3 >> 3) ^ t3) >> 1) ^ t3
		feedback = (feedback >> 8) ^ t3
		t6 := (feedback >> 5) & 0xff
		t3 = (t3 << 8) | t6
		t6 = uint32(bitReverse(byte(t6)))
		t5 += t6 + t4
		out[i] = byte(t5)
		t5 >>= 8
	}
	return out
}
