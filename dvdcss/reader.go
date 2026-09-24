package dvdcss

import (
	"fmt"
	"io"
	"os"
)

const (
	NoFlags     = 0
	ReadDecrypt = 1 << (iota - 1)
	SeekMPEG    = 1 << (iota - 1)
	SeekKey     = 1 << (iota - 1)
)

type DVD struct {
	fd         *uintptr
	stream     io.ReadSeeker
	position   int64
	agid       int
	busKey     Key
	discKey    Key
	discKnown  bool
	titleKey   Key
	titleKnown bool
	scrambled  scrambleState
}

type scrambleState uint8

const (
	scrambleUnknown scrambleState = iota
	scrambleClear
	scrambleEncrypted
)

func Open(path string) (*DVD, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	fd := file.Fd()
	dvd := &DVD{fd: &fd, stream: file, scrambled: scrambleUnknown}
	dvd.detectScrambled()
	return dvd, nil
}

func New(stream io.ReadSeeker) *DVD {
	return &DVD{stream: stream, scrambled: scrambleUnknown}
}

func (dvd *DVD) SetFd(fd uintptr) error {
	if dvd.fd != nil {
		return fmt.Errorf("dvdcss: file descriptor already set")
	}
	dvd.fd = &fd
	dvd.detectScrambled()
	return nil
}

func (dvd *DVD) Close() error {
	if dvd.fd == nil {
		return nil
	}
	closer, ok := dvd.stream.(io.Closer)
	if !ok {
		return fmt.Errorf("dvdcss: opened stream cannot be closed")
	}
	err := closer.Close()
	dvd.fd = nil
	dvd.stream = nil
	return err
}

func (dvd *DVD) Seek(block int64, flags int) (int64, error) {
	if block < 0 {
		return -1, fmt.Errorf("dvdcss: negative block %d", block)
	}
	if _, err := dvd.stream.Seek(block*BlockSize, io.SeekStart); err != nil {
		return -1, err
	}
	dvd.position = block
	dvd.detectScrambled()
	dvd.detectScrambledAt(block)
	if flags&(SeekMPEG|SeekKey) != 0 {
		if dvd.scrambled != scrambleClear && !dvd.tryTitleKey(block) {
			if err := dvd.ensureTitleKey(block); err != nil {
				return -1, err
			}
		}
	}
	return block, nil
}

func (dvd *DVD) tryTitleKey(block int64) bool {
	if dvd.fd == nil || dvd.titleKnown {
		return dvd.titleKnown
	}
	if !dvd.discKnown {
		if err := dvd.loadDiscKey(); err != nil {
			return false
		}
	}
	agid, busKey, err := authenticate(*dvd.fd)
	if err != nil {
		return false
	}
	dvd.agid, dvd.busKey = agid, busKey
	key, err := readTitleKey(*dvd.fd, dvd.agid, int(block))
	if err != nil {
		return false
	}
	asf, err := reportASF(*dvd.fd)
	if err != nil || asf != 1 {
		_ = invalidateAGID(*dvd.fd, dvd.agid)
		return false
	}
	for i := range key {
		key[i] ^= dvd.busKey[4-i]
	}
	if key.IsZero() {
		return false
	}
	dvd.titleKey = decryptTitleKey(dvd.discKey, key)
	dvd.titleKnown = true
	return true
}

func (dvd *DVD) ensureTitleKeyForRead() error {
	if dvd.tryTitleKey(dvd.position) {
		return nil
	}
	if err := dvd.ensureTitleKey(dvd.position); err != nil {
		return err
	}
	return nil
}

func (dvd *DVD) detectScrambled() {
	if dvd.scrambled != scrambleUnknown || dvd.fd == nil {
		return
	}
	if copyright, err := readCopyright(*dvd.fd, 0); err == nil {
		if copyright == 0 {
			dvd.scrambled = scrambleClear
		} else {
			dvd.scrambled = scrambleEncrypted
		}
	}
}

func (dvd *DVD) detectScrambledAt(block int64) {
	if dvd.scrambled != scrambleUnknown {
		return
	}
	var sector [BlockSize]byte
	if _, err := dvd.stream.Seek(block*BlockSize, io.SeekStart); err != nil {
		return
	}
	n, err := io.ReadFull(dvd.stream, sector[:])
	_, _ = dvd.stream.Seek(block*BlockSize, io.SeekStart)
	if err != nil || n != BlockSize {
		return
	}
	if sector[0x14]&0x30 != 0 {
		dvd.scrambled = scrambleEncrypted
	} else {
		dvd.scrambled = scrambleClear
	}
}

func (dvd *DVD) classifyBuffer(buffer []byte, blocks int) {
	if dvd.scrambled != scrambleUnknown {
		return
	}
	for i := 0; i < blocks; i++ {
		if buffer[i*BlockSize+0x14]&0x30 != 0 {
			dvd.scrambled = scrambleEncrypted
			return
		}
	}
	if blocks > 0 {
		dvd.scrambled = scrambleClear
	}
}

func (dvd *DVD) Read(buffer []byte, blocks int, flags int) (int, error) {
	if blocks < 0 || len(buffer) < blocks*BlockSize {
		return 0, fmt.Errorf("dvdcss: buffer is too small for %d blocks", blocks)
	}
	dvd.detectScrambled()
	readStart := dvd.position
	if dvd.scrambled == scrambleEncrypted && flags&ReadDecrypt != 0 && !dvd.titleKnown {
		if err := dvd.ensureTitleKeyForRead(); err != nil {
			return 0, err
		}
	}
	n, err := io.ReadFull(dvd.stream, buffer[:blocks*BlockSize])
	readBlocks := n / BlockSize
	dvd.position += int64(readBlocks)
	dvd.classifyBuffer(buffer, readBlocks)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return readBlocks, err
	}
	if dvd.scrambled == scrambleEncrypted && flags&ReadDecrypt != 0 && !dvd.titleKnown {
		if !dvd.tryTitleKey(readStart) {
			if err := dvd.ensureTitleKey(readStart); err != nil {
				return 0, err
			}
		}
	}
	if dvd.scrambled == scrambleEncrypted && flags&ReadDecrypt != 0 {
		for i := 0; i < readBlocks; i++ {
			sector := buffer[i*BlockSize : (i+1)*BlockSize]
			if err := unscramble(dvd.titleKey, sector); err != nil {
				return i, err
			}
			sector[0x14] &= 0x8f
		}
	}
	return readBlocks, nil
}

func (dvd *DVD) ensureTitleKey(start int64) error {
	if dvd.titleKnown {
		return nil
	}
	original := dvd.position
	defer func() {
		_, _ = dvd.stream.Seek(original*BlockSize, io.SeekStart)
		dvd.position = original
	}()

	const readLimit = 4718592
	var sector [BlockSize]byte
	encryptedSeen := false
	for scanned := int64(0); scanned < readLimit; scanned++ {
		block := start + int64(scanned)
		if _, err := dvd.stream.Seek(block*BlockSize, io.SeekStart); err != nil {
			return err
		}
		if _, err := io.ReadFull(dvd.stream, sector[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return err
		}
		if sector[0] != 0 || sector[1] != 0 || sector[2] != 1 {
			break
		}
		if sector[0x14]&0x30 == 0 || sector[0x11] == 0xbb || sector[0x11] == 0xbe || sector[0x11] == 0xbf {
			continue
		}
		encryptedSeen = true
		if key, ok := attackPattern(sector[:]); ok {
			dvd.titleKey = key
			dvd.titleKnown = true
			return nil
		}
	}
	if encryptedSeen {
		return fmt.Errorf("dvdcss: unable to recover title key")
	}
	dvd.titleKnown = true
	return nil
}

func attackPattern(sector []byte) (Key, bool) {
	bestLength, bestPeriod := 0, 0
	for period := 2; period < 0x30; period++ {
		for length := period + 1; length < 0x80 && sector[0x7f-(length%period)] == sector[0x7f-length]; length++ {
			if length > bestLength {
				bestLength, bestPeriod = length, period
			}
		}
	}
	if bestLength <= 3 || bestLength/bestPeriod < 2 {
		return Key{}, false
	}
	key, _, err := recoverTitleKey(0, sector[0x80:], sector[0x80-(bestLength/bestPeriod)*bestPeriod:], sector[0x54:])
	return key, err == nil
}
