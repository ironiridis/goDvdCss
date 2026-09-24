package dvdcss

import "errors"

const (
	BlockSize = 2048
	KeySize   = 5
)

type Key [KeySize]byte

func (key Key) IsZero() bool {
	for _, value := range key {
		if value != 0 {
			return false
		}
	}
	return true
}

func decryptKey(invert byte, key Key, crypted Key) Key {
	var result, stream [KeySize]byte
	lfsr1lo := uint32(key[0]) | 0x100
	lfsr1hi := uint32(key[1])
	lfsr0 := (uint32(key[4])<<17 | uint32(key[3])<<9 | uint32(key[2])<<1) + 8 - uint32(key[2]&7)
	lfsr0 = uint32(bitReverse(byte(lfsr0)))<<24 | uint32(bitReverse(byte(lfsr0>>8)))<<16 | uint32(bitReverse(byte(lfsr0>>16)))<<8 | uint32(bitReverse(byte(lfsr0>>24)))
	combined := uint32(0)
	for i := 0; i < KeySize; i++ {
		out1 := uint32(cssTab2[byte(lfsr1hi)]) ^ uint32(cssTab3[lfsr1lo])
		lfsr1hi = lfsr1lo >> 1
		lfsr1lo = ((lfsr1lo & 1) << 8) ^ out1
		out1 = uint32(cssTab4[byte(out1)])
		out0 := (((((lfsr0>>8)^lfsr0)>>1)^lfsr0)>>3 ^ lfsr0) >> 7
		lfsr0 = lfsr0>>8 | out0<<24
		combined += (out0 ^ uint32(invert)) + out1
		stream[i] = byte(combined)
		combined >>= 8
	}
	result[4] = stream[4] ^ cssTab1[crypted[4]] ^ crypted[3]
	result[3] = stream[3] ^ cssTab1[crypted[3]] ^ crypted[2]
	result[2] = stream[2] ^ cssTab1[crypted[2]] ^ crypted[1]
	result[1] = stream[1] ^ cssTab1[crypted[1]] ^ crypted[0]
	result[0] = stream[0] ^ cssTab1[crypted[0]] ^ result[4]
	result[4] = stream[4] ^ cssTab1[result[4]] ^ result[3]
	result[3] = stream[3] ^ cssTab1[result[3]] ^ result[2]
	result[2] = stream[2] ^ cssTab1[result[2]] ^ result[1]
	result[1] = stream[1] ^ cssTab1[result[1]] ^ result[0]
	result[0] = stream[0] ^ cssTab1[result[0]]
	return result
}

func decryptTitleKey(discKey, encrypted Key) Key { return decryptKey(0xff, discKey, encrypted) }

func decryptDiscKey(encrypted []byte) (Key, error) {
	if len(encrypted) < 5*409 {
		return Key{}, errors.New("dvdcss: disc key structure is too short")
	}
	for _, playerKey := range playerKeys {
		for position := 1; position < 409; position++ {
			candidate := decryptKey(0, playerKey, Key(encrypted[position*5:position*5+5]))
			verify := decryptKey(0, candidate, Key(encrypted[:5]))
			if candidate == verify {
				return candidate, nil
			}
		}
	}
	return Key{}, errors.New("dvdcss: no player key decrypted the disc key")
}

// recoverTitleKey reconstructs a CSS title key from ten encrypted bytes and
// their known plaintext, using the sector seed at offset 0x54.
func recoverTitleKey(start int, crypted, decrypted, sectorSeed []byte) (Key, int, error) {
	if start < 0 || start > 0xffff || len(crypted) < 10 || len(decrypted) < 10 || len(sectorSeed) < KeySize {
		return Key{}, -1, errors.New("dvdcss: invalid title-key recovery input")
	}
	var buffer [10]byte
	for i := range buffer {
		buffer[i] = cssTab1[crypted[i]] ^ decrypted[i]
	}
	for attempt := start; attempt < 0x10000; attempt++ {
		t1, t2, t3, t5 := uint32(attempt>>8)|0x100, uint32(attempt&0xff), uint32(0), uint32(0)
		var candidate uint32
		valid := true
		for i := 0; i < 10; i++ {
			t4 := uint32(cssTab2[byte(t2)]) ^ uint32(cssTab3[t1])
			t2, t1 = t1>>1, ((t1&1)<<8)^t4
			t4 = uint32(cssTab5[byte(t4)])
			var t6 uint32
			if i < 4 {
				t6 = uint32(buffer[i])
				if t5 != 0 {
					t6 = (t6 + 0xff) & 0xff
				}
				if t6 < t4 {
					t6 += 0x100
				}
				t6 -= t4
				t5 += t6 + t4
				t3 = t3<<8 | uint32(cssTab4[byte(t6)])
				t5 >>= 8
				continue
			}
			feedback := (((t3 >> 3) ^ t3) >> 1) ^ t3
			feedback = (feedback >> 8) ^ t3
			t3 = t3<<8 | feedback&0xff
			t6 = uint32(cssTab4[byte(feedback>>5)])
			t5 += t6 + t4
			if byte(t5) != buffer[i] {
				valid = false
				break
			}
			t5 >>= 8
		}
		if !valid {
			continue
		}
		candidate = t3
		for i := 0; i < 4; i++ {
			wanted := candidate & 0xff
			candidate >>= 8
			for input := uint32(0); input < 256; input++ {
				state := (candidate & 0x1ffff) | input<<17
				feedback := (((state >> 3) ^ state) >> 1) ^ state
				feedback = (feedback >> 8) ^ state
				if feedback&0xff == wanted {
					candidate = state
					break
				}
			}
		}
		base := (candidate >> 1) - 4
		for offset := uint32(0); offset < 8; offset++ {
			state := base + offset
			if (state*2 + 8 - (state & 7)) == candidate {
				key := Key{byte(attempt >> 8), byte(attempt), byte(state), byte(state >> 8), byte(state >> 16)}
				for i := range key {
					key[i] ^= sectorSeed[i]
				}
				return key, attempt + 1, nil
			}
		}
	}
	return Key{}, -1, errors.New("dvdcss: title-key recovery failed")
}

func unscramble(key Key, sector []byte) error {
	if len(sector) < BlockSize {
		return errors.New("dvdcss: sector is shorter than 2048 bytes")
	}
	if sector[0x14]&0x30 == 0 {
		return nil
	}
	t1 := uint32(key[0]^sector[0x54]) | 0x100
	t2 := uint32(key[1] ^ sector[0x55])
	t3 := (uint32(key[2]) | uint32(key[3])<<8 | uint32(key[4])<<16) ^ (uint32(sector[0x56]) | uint32(sector[0x57])<<8 | uint32(sector[0x58])<<16)
	t3 = t3*2 + 8 - (t3 & 7)
	t5 := uint32(0)
	for i := 0x80; i < BlockSize; i++ {
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
		sector[i] = cssTab1[sector[i]] ^ byte(t5)
		t5 >>= 8
	}
	return nil
}

func bitReverse(value byte) byte {
	value = value>>4 | value<<4
	value = value>>2&0x33 | value<<2&0xcc
	return value>>1&0x55 | value<<1&0xaa
}

// Source: upstream/libdvdcss/src/csstables.h:36 (p_css_tab1).
const cssTab1 = "\x33\x73\x3b\x26\x63\x23\x6b\x76\x3e\x7e\x36\x2b\x6e\x2e\x66\x7b" +
	"\xd3\x93\xdb\x06\x43\x03\x4b\x96\xde\x9e\xd6\x0b\x4e\x0e\x46\x9b" +
	"\x57\x17\x5f\x82\xc7\x87\xcf\x12\x5a\x1a\x52\x8f\xca\x8a\xc2\x1f" +
	"\xd9\x99\xd1\x00\x49\x09\x41\x90\xd8\x98\xd0\x01\x48\x08\x40\x91" +
	"\x3d\x7d\x35\x24\x6d\x2d\x65\x74\x3c\x7c\x34\x25\x6c\x2c\x64\x75" +
	"\xdd\x9d\xd5\x04\x4d\x0d\x45\x94\xdc\x9c\xd4\x05\x4c\x0c\x44\x95" +
	"\x59\x19\x51\x80\xc9\x89\xc1\x10\x58\x18\x50\x81\xc8\x88\xc0\x11" +
	"\xd7\x97\xdf\x02\x47\x07\x4f\x92\xda\x9a\xd2\x0f\x4a\x0a\x42\x9f" +
	"\x53\x13\x5b\x86\xc3\x83\xcb\x16\x5e\x1e\x56\x8b\xce\x8e\xc6\x1b" +
	"\xb3\xf3\xbb\xa6\xe3\xa3\xeb\xf6\xbe\xfe\xb6\xab\xee\xae\xe6\xfb" +
	"\x37\x77\x3f\x22\x67\x27\x6f\x72\x3a\x7a\x32\x2f\x6a\x2a\x62\x7f" +
	"\xb9\xf9\xb1\xa0\xe9\xa9\xe1\xf0\xb8\xf8\xb0\xa1\xe8\xa8\xe0\xf1" +
	"\x5d\x1d\x55\x84\xcd\x8d\xc5\x14\x5c\x1c\x54\x85\xcc\x8c\xc4\x15" +
	"\xbd\xfd\xb5\xa4\xed\xad\xe5\xf4\xbc\xfc\xb4\xa5\xec\xac\xe4\xf5" +
	"\x39\x79\x31\x20\x69\x29\x61\x70\x38\x78\x30\x21\x68\x28\x60\x71" +
	"\xb7\xf7\xbf\xa2\xe7\xa7\xef\xf2\xba\xfa\xb2\xaf\xea\xaa\xe2\xff"

// Source: upstream/libdvdcss/src/csstables.h:72 (p_css_tab2).
var cssTab2 = [256]byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09, 0x08, 0x0b, 0x0a, 0x0d, 0x0c, 0x0f, 0x0e,
	0x12, 0x13, 0x10, 0x11, 0x16, 0x17, 0x14, 0x15, 0x1b, 0x1a, 0x19, 0x18, 0x1f, 0x1e, 0x1d, 0x1c,
	0x24, 0x25, 0x26, 0x27, 0x20, 0x21, 0x22, 0x23, 0x2d, 0x2c, 0x2f, 0x2e, 0x29, 0x28, 0x2b, 0x2a,
	0x36, 0x37, 0x34, 0x35, 0x32, 0x33, 0x30, 0x31, 0x3f, 0x3e, 0x3d, 0x3c, 0x3b, 0x3a, 0x39, 0x38,
	0x49, 0x48, 0x4b, 0x4a, 0x4d, 0x4c, 0x4f, 0x4e, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
	0x5b, 0x5a, 0x59, 0x58, 0x5f, 0x5e, 0x5d, 0x5c, 0x52, 0x53, 0x50, 0x51, 0x56, 0x57, 0x54, 0x55,
	0x6d, 0x6c, 0x6f, 0x6e, 0x69, 0x68, 0x6b, 0x6a, 0x64, 0x65, 0x66, 0x67, 0x60, 0x61, 0x62, 0x63,
	0x7f, 0x7e, 0x7d, 0x7c, 0x7b, 0x7a, 0x79, 0x78, 0x76, 0x77, 0x74, 0x75, 0x72, 0x73, 0x70, 0x71,
	0x92, 0x93, 0x90, 0x91, 0x96, 0x97, 0x94, 0x95, 0x9b, 0x9a, 0x99, 0x98, 0x9f, 0x9e, 0x9d, 0x9c,
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x89, 0x88, 0x8b, 0x8a, 0x8d, 0x8c, 0x8f, 0x8e,
	0xb6, 0xb7, 0xb4, 0xb5, 0xb2, 0xb3, 0xb0, 0xb1, 0xbf, 0xbe, 0xbd, 0xbc, 0xbb, 0xba, 0xb9, 0xb8,
	0xa4, 0xa5, 0xa6, 0xa7, 0xa0, 0xa1, 0xa2, 0xa3, 0xad, 0xac, 0xaf, 0xae, 0xa9, 0xa8, 0xab, 0xaa,
	0xdb, 0xda, 0xd9, 0xd8, 0xdf, 0xde, 0xdd, 0xdc, 0xd2, 0xd3, 0xd0, 0xd1, 0xd6, 0xd7, 0xd4, 0xd5,
	0xc9, 0xc8, 0xcb, 0xca, 0xcd, 0xcc, 0xcf, 0xce, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
	0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf6, 0xf7, 0xf4, 0xf5, 0xf2, 0xf3, 0xf0, 0xf1,
	0xed, 0xec, 0xef, 0xee, 0xe9, 0xe8, 0xeb, 0xea, 0xe4, 0xe5, 0xe6, 0xe7, 0xe0, 0xe1, 0xe2, 0xe3,
}

// Source: upstream/libdvdcss/src/csstables.h:108 (p_css_tab3).
const cssTab3Pattern = "\x00\x24\x49\x6d\x92\xb6\xdb\xff"

// Go has no constant array type. Strings provide immutable byte tables and
// preserve the original C table data without runtime initialization.
const cssTab3 = cssTab3Pattern + cssTab3Pattern + cssTab3Pattern + cssTab3Pattern +
	cssTab3Pattern + cssTab3Pattern + cssTab3Pattern + cssTab3Pattern +
	cssTab3Pattern + cssTab3Pattern + cssTab3Pattern + cssTab3Pattern +
	cssTab3Pattern + cssTab3Pattern + cssTab3Pattern + cssTab3Pattern +
	cssTab3Pattern + cssTab3Pattern + cssTab3Pattern + cssTab3Pattern +
	cssTab3Pattern + cssTab3Pattern + cssTab3Pattern + cssTab3Pattern +
	cssTab3Pattern + cssTab3Pattern + cssTab3Pattern + cssTab3Pattern +
	cssTab3Pattern + cssTab3Pattern + cssTab3Pattern + cssTab3Pattern +
	cssTab3Pattern + cssTab3Pattern + cssTab3Pattern + cssTab3Pattern +
	cssTab3Pattern + cssTab3Pattern + cssTab3Pattern + cssTab3Pattern +
	cssTab3Pattern + cssTab3Pattern + cssTab3Pattern + cssTab3Pattern +
	cssTab3Pattern + cssTab3Pattern + cssTab3Pattern + cssTab3Pattern +
	cssTab3Pattern + cssTab3Pattern + cssTab3Pattern + cssTab3Pattern +
	cssTab3Pattern + cssTab3Pattern + cssTab3Pattern + cssTab3Pattern +
	cssTab3Pattern + cssTab3Pattern + cssTab3Pattern + cssTab3Pattern +
	cssTab3Pattern + cssTab3Pattern + cssTab3Pattern + cssTab3Pattern

// Source: upstream/libdvdcss/src/csstables.h:176 (p_css_tab4).
const cssTab4 = "\x00\x80\x40\xc0\x20\xa0\x60\xe0\x10\x90\x50\xd0\x30\xb0\x70\xf0" +
	"\x08\x88\x48\xc8\x28\xa8\x68\xe8\x18\x98\x58\xd8\x38\xb8\x78\xf8" +
	"\x04\x84\x44\xc4\x24\xa4\x64\xe4\x14\x94\x54\xd4\x34\xb4\x74\xf4" +
	"\x0c\x8c\x4c\xcc\x2c\xac\x6c\xec\x1c\x9c\x5c\xdc\x3c\xbc\x7c\xfc" +
	"\x02\x82\x42\xc2\x22\xa2\x62\xe2\x12\x92\x52\xd2\x32\xb2\x72\xf2" +
	"\x0a\x8a\x4a\xca\x2a\xaa\x6a\xea\x1a\x9a\x5a\xda\x3a\xba\x7a\xfa" +
	"\x06\x86\x46\xc6\x26\xa6\x66\xe6\x16\x96\x56\xd6\x36\xb6\x76\xf6" +
	"\x0e\x8e\x4e\xce\x2e\xae\x6e\xee\x1e\x9e\x5e\xde\x3e\xbe\x7e\xfe" +
	"\x01\x81\x41\xc1\x21\xa1\x61\xe1\x11\x91\x51\xd1\x31\xb1\x71\xf1" +
	"\x09\x89\x49\xc9\x29\xa9\x69\xe9\x19\x99\x59\xd9\x39\xb9\x79\xf9" +
	"\x05\x85\x45\xc5\x25\xa5\x65\xe5\x15\x95\x55\xd5\x35\xb5\x75\xf5" +
	"\x0d\x8d\x4d\xcd\x2d\xad\x6d\xed\x1d\x9d\x5d\xdd\x3d\xbd\x7d\xfd" +
	"\x03\x83\x43\xc3\x23\xa3\x63\xe3\x13\x93\x53\xd3\x33\xb3\x73\xf3" +
	"\x0b\x8b\x4b\xcb\x2b\xab\x6b\xeb\x1b\x9b\x5b\xdb\x3b\xbb\x7b\xfb" +
	"\x07\x87\x47\xc7\x27\xa7\x67\xe7\x17\x97\x57\xd7\x37\xb7\x77\xf7" +
	"\x0f\x8f\x4f\xcf\x2f\xaf\x6f\xef\x1f\x9f\x5f\xdf\x3f\xbf\x7f\xff"

// Source: upstream/libdvdcss/src/csstables.h:212 (p_css_tab5).
const cssTab5 = "\xff\x7f\xbf\x3f\xdf\x5f\x9f\x1f\xef\x6f\xaf\x2f\xcf\x4f\x8f\x0f" +
	"\xf7\x77\xb7\x37\xd7\x57\x97\x17\xe7\x67\xa7\x27\xc7\x47\x87\x07" +
	"\xfb\x7b\xbb\x3b\xdb\x5b\x9b\x1b\xeb\x6b\xab\x2b\xcb\x4b\x8b\x0b" +
	"\xf3\x73\xb3\x33\xd3\x53\x93\x13\xe3\x63\xa3\x23\xc3\x43\x83\x03" +
	"\xfd\x7d\xbd\x3d\xdd\x5d\x9d\x1d\xed\x6d\xad\x2d\xcd\x4d\x8d\x0d" +
	"\xf5\x75\xb5\x35\xd5\x55\x95\x15\xe5\x65\xa5\x25\xc5\x45\x85\x05" +
	"\xf9\x79\xb9\x39\xd9\x59\x99\x19\xe9\x69\xa9\x29\xc9\x49\x89\x09" +
	"\xf1\x71\xb1\x31\xd1\x51\x91\x11\xe1\x61\xa1\x21\xc1\x41\x81\x01" +
	"\xfe\x7e\xbe\x3e\xde\x5e\x9e\x1e\xee\x6e\xae\x2e\xce\x4e\x8e\x0e" +
	"\xf6\x76\xb6\x36\xd6\x56\x96\x16\xe6\x66\xa6\x26\xc6\x46\x86\x06" +
	"\xfa\x7a\xba\x3a\xda\x5a\x9a\x1a\xea\x6a\xaa\x2a\xca\x4a\x8a\x0a" +
	"\xf2\x72\xb2\x32\xd2\x52\x92\x12\xe2\x62\xa2\x22\xc2\x42\x82\x02" +
	"\xfc\x7c\xbc\x3c\xdc\x5c\x9c\x1c\xec\x6c\xac\x2c\xcc\x4c\x8c\x0c" +
	"\xf4\x74\xb4\x34\xd4\x54\x94\x14\xe4\x64\xa4\x24\xc4\x44\x84\x04" +
	"\xf8\x78\xb8\x38\xd8\x58\x98\x18\xe8\x68\xa8\x28\xc8\x48\x88\x08" +
	"\xf0\x70\xb0\x30\xd0\x50\x90\x10\xe0\x60\xa0\x20\xc0\x40\x80\x00"

var playerKeys = [...]Key{
	{0x01, 0xaf, 0xe3, 0x12, 0x80}, {0x12, 0x11, 0xca, 0x04, 0x3b}, {0x14, 0x0c, 0x9e, 0xd0, 0x09}, {0x14, 0x71, 0x35, 0xba, 0xe2},
	{0x1a, 0xa4, 0x33, 0x21, 0xa6}, {0x26, 0xec, 0xc4, 0xa7, 0x4e}, {0x2c, 0xb2, 0xc1, 0x09, 0xee}, {0x2f, 0x25, 0x9e, 0x96, 0xdd},
	{0x33, 0x2f, 0x49, 0x6c, 0xe0}, {0x35, 0x5b, 0xc1, 0x31, 0x0f}, {0x36, 0x67, 0xb2, 0xe3, 0x85}, {0x39, 0x3d, 0xf1, 0xf1, 0xbd},
	{0x3b, 0x31, 0x34, 0x0d, 0x91}, {0x45, 0xed, 0x28, 0xeb, 0xd3}, {0x48, 0xb7, 0x6c, 0xce, 0x69}, {0x4b, 0x65, 0x0d, 0xc1, 0xee},
	{0x4c, 0xbb, 0xf5, 0x5b, 0x23}, {0x51, 0x67, 0x67, 0xc5, 0xe0}, {0x53, 0x94, 0xe1, 0x75, 0xbf}, {0x57, 0x2c, 0x8b, 0x31, 0xae},
	{0x63, 0xdb, 0x4c, 0x5b, 0x4a}, {0x7b, 0x1e, 0x5e, 0x2b, 0x57}, {0x85, 0xf3, 0x85, 0xa0, 0xe0}, {0xab, 0x1e, 0xe7, 0x7b, 0x72},
	{0xab, 0x36, 0xe3, 0xeb, 0x76}, {0xb1, 0xb8, 0xf9, 0x38, 0x03}, {0xb8, 0x5d, 0xd8, 0x53, 0xbd}, {0xbf, 0x92, 0xc3, 0xb0, 0xe2},
	{0xcf, 0x1a, 0xb2, 0xf8, 0x0a}, {0xec, 0xa0, 0xcf, 0xb3, 0xff}, {0xfc, 0x95, 0xa9, 0x87, 0x35},
}
