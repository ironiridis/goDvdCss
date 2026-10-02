package dvdcss

import (
	"fmt"
	"io"
	"log/slog"
	"os"
)

const (
	NoFlags     = 0
	ReadDecrypt = 1 << (iota - 1)
	SeekMPEG    = 1 << (iota - 1)
	SeekKey     = 1 << (iota - 1)
)

type DVD struct {
	fd          *uintptr
	stream      io.ReadSeeker
	position    int64
	agid        int
	busKey      Key
	discKey     Key
	discKnown   bool
	titleKey    Key
	titleKnown  bool
	titleKeys   map[int64]Key
	sectorCount int64
	sizeErr     error
	scrambled   scrambleState
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
		slog.Debug("dvdcss: failed to open path", "path", path, "err", err)
		return nil, err
	}
	fd := file.Fd()
	dvd := &DVD{fd: &fd, stream: file, scrambled: scrambleUnknown}
	if err := dvd.initializeSectorCount(); err != nil {
		_ = file.Close()
		return nil, err
	}
	dvd.detectScrambled()
	return dvd, nil
}

func New(stream io.ReadSeeker) *DVD {
	dvd := &DVD{stream: stream, scrambled: scrambleUnknown}
	dvd.sizeErr = dvd.initializeSectorCount()
	return dvd
}

func (dvd *DVD) initializeSectorCount() error {
	if dvd.stream == nil {
		return fmt.Errorf("dvdcss: source stream is nil")
	}
	position, err := dvd.stream.Seek(0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("dvdcss: get source position: %w", err)
	}
	size, err := dvd.stream.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("dvdcss: get source size: %w", err)
	}
	if _, err := dvd.stream.Seek(position, io.SeekStart); err != nil {
		return fmt.Errorf("dvdcss: restore source position: %w", err)
	}
	dvd.sectorCount = size / BlockSize
	return nil
}

func (dvd *DVD) SetFd(fd uintptr) error {
	if dvd.fd != nil {
		slog.Debug("dvdcss: file descriptor already set", "fd", *dvd.fd)
		return fmt.Errorf("dvdcss: file descriptor already set")
	}
	dvd.fd = &fd
	dvd.detectScrambled()
	return nil
}

// Eject opens the DVD tray when retract is false and closes it when true.
func (dvd *DVD) Eject(retract bool) error {
	if dvd.fd == nil {
		err := fmt.Errorf("dvdcss: file descriptor is not set")
		slog.Debug("dvdcss: cannot control tray without a file descriptor", "err", err)
		return err
	}
	if !retract {
		if err := ejectTray(*dvd.fd); err != nil {
			slog.Debug("dvdcss: failed to eject tray", "err", err)
			return err
		}
	} else {
		if err := closeTray(*dvd.fd); err != nil {
			slog.Debug("dvdcss: failed to retract tray", "err", err)
			return err
		}
	}
	return nil
}

func (dvd *DVD) Close() error {
	if dvd.fd == nil {
		return nil
	}
	closer, ok := dvd.stream.(io.Closer)
	if !ok {
		slog.Debug("dvdcss: opened stream cannot be closed", "streamType", fmt.Sprintf("%T", dvd.stream))
		return fmt.Errorf("dvdcss: opened stream cannot be closed")
	}
	err := closer.Close()
	dvd.fd = nil
	dvd.stream = nil
	return err
}

func (dvd *DVD) Seek(block int64, flags int) (int64, error) {
	if block < 0 {
		slog.Debug("dvdcss: negative block", "block", block)
		return -1, fmt.Errorf("dvdcss: negative block %d", block)
	}
	if _, err := dvd.stream.Seek(block*BlockSize, io.SeekStart); err != nil {
		slog.Debug("dvdcss: seek failed", "block", block, "err", err)
		return -1, err
	}
	dvd.position = block
	dvd.detectScrambled()
	dvd.detectScrambledAt(block)
	if flags&(SeekMPEG|SeekKey) != 0 {
		if dvd.scrambled != scrambleClear && !dvd.tryTitleKey(block) {
			if err := dvd.ensureTitleKey(block); err != nil {
				slog.Debug("dvdcss: failed to ensure title key during seek", "block", block, "err", err)
				return -1, err
			}
		}
	}
	return block, nil
}

func (dvd *DVD) tryTitleKey(block int64) bool {
	if dvd.useTitleKey(block) {
		return true
	}
	if dvd.fd == nil {
		return false
	}
	if !dvd.discKnown {
		if err := dvd.loadDiscKey(); err != nil {
			slog.Debug("dvdcss: failed to load disc key", "block", block, "err", err)
			return false
		}
	}
	agid, busKey, err := authenticate(*dvd.fd)
	if err != nil {
		slog.Debug("dvdcss: authentication failed while fetching title key", "block", block, "err", err)
		return false
	}
	dvd.agid, dvd.busKey = agid, busKey
	key, err := readTitleKey(*dvd.fd, dvd.agid, int(block))
	if err != nil {
		slog.Debug("dvdcss: failed to read title key", "block", block, "err", err)
		return false
	}
	asf, err := reportASF(*dvd.fd)
	if err != nil {
		slog.Debug("dvdcss: failed to report authentication success flag while fetching title key", "block", block, "err", err)
		_ = invalidateAGID(*dvd.fd, dvd.agid)
		return false
	}
	if asf == 0 {
		slog.Debug("dvdcss: authentication success flag cleared while fetching title key", "block", block)
	}
	for i := range key {
		key[i] ^= dvd.busKey[4-i]
	}
	if key.IsZero() {
		slog.Debug("dvdcss: title is not encrypted", "block", block)
		dvd.rememberTitleKey(block, key)
		return true
	}
	dvd.rememberTitleKey(block, decryptTitleKey(dvd.discKey, key))
	return true
}

func (dvd *DVD) useTitleKey(block int64) bool {
	key, ok := dvd.titleKeys[block]
	if !ok {
		return false
	}
	dvd.titleKey = key
	dvd.titleKnown = true
	return true
}

func (dvd *DVD) rememberTitleKey(block int64, key Key) {
	if dvd.titleKeys == nil {
		dvd.titleKeys = make(map[int64]Key)
	}
	dvd.titleKeys[block] = key
	dvd.titleKey = key
	dvd.titleKnown = true
}

func (dvd *DVD) ensureTitleKeyForRead() error {
	if dvd.tryTitleKey(dvd.position) {
		return nil
	}
	if err := dvd.ensureTitleKey(dvd.position); err != nil {
		slog.Debug("dvdcss: failed to ensure title key for read", "position", dvd.position, "err", err)
		return err
	}
	return nil
}

func (dvd *DVD) detectScrambled() {
	if dvd.scrambled != scrambleUnknown || dvd.fd == nil {
		return
	}
	copyright, err := readCopyright(*dvd.fd, 0)
	if err != nil {
		return
	}
	if copyright == 0 {
		dvd.scrambled = scrambleClear
	} else {
		dvd.scrambled = scrambleEncrypted
	}
	dvd.checkRegion(copyright)
}

// checkRegion logs the drive's RPC status, matching dvdcss_test's warning
// that a scrambled disc on a region-free RPC-II drive may fail to read.
func (dvd *DVD) checkRegion(copyright int) {
	typ, mask, rpc, err := reportRPC(*dvd.fd)
	if err != nil {
		slog.Debug("dvdcss: could not get RPC status, assuming RPC-I drive", "err", err)
		return
	}
	slog.Debug("dvdcss: drive region status", "type", typ, "mask", mask, "rpcScheme", rpc)
	if copyright != 0 && rpc == 1 && typ == 0 {
		slog.Debug("dvdcss: scrambled disc on a region-free RPC-II drive: possible failure, but continuing anyway")
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
	for i := range blocks {
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
		slog.Debug("dvdcss: buffer is too small", "blocks", blocks, "bufferLen", len(buffer))
		return 0, fmt.Errorf("dvdcss: buffer is too small for %d blocks", blocks)
	}
	dvd.detectScrambled()
	readStart := dvd.position
	if dvd.scrambled == scrambleEncrypted && flags&ReadDecrypt != 0 && !dvd.titleKnown {
		if err := dvd.ensureTitleKeyForRead(); err != nil {
			slog.Debug("dvdcss: failed to ensure title key before read", "position", readStart, "err", err)
			return 0, err
		}
	}
	n, err := io.ReadFull(dvd.stream, buffer[:blocks*BlockSize])
	readBlocks := n / BlockSize
	dvd.position += int64(readBlocks)
	dvd.classifyBuffer(buffer, readBlocks)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		slog.Debug("dvdcss: read failed", "position", readStart, "blocks", blocks, "err", err)
		return readBlocks, err
	}
	if dvd.scrambled == scrambleEncrypted && flags&ReadDecrypt != 0 && !dvd.titleKnown {
		if !dvd.tryTitleKey(readStart) {
			if err := dvd.ensureTitleKey(readStart); err != nil {
				slog.Debug("dvdcss: failed to ensure title key after read", "position", readStart, "err", err)
				return 0, err
			}
		}
	}
	if dvd.scrambled == scrambleEncrypted && flags&ReadDecrypt != 0 {
		for i := range readBlocks {
			sector := buffer[i*BlockSize : (i+1)*BlockSize]
			if err := unscramble(dvd.titleKey, sector); err != nil {
				slog.Debug("dvdcss: failed to unscramble sector", "position", readStart, "index", i, "err", err)
				return i, err
			}
			sector[0x14] &= 0x8f
		}
	}
	return readBlocks, nil
}

func (dvd *DVD) ensureTitleKey(start int64) error {
	if dvd.useTitleKey(start) {
		return nil
	}
	if dvd.sizeErr != nil {
		return dvd.sizeErr
	}
	original := dvd.position
	defer func() {
		_, _ = dvd.stream.Seek(original*BlockSize, io.SeekStart)
		dvd.position = original
	}()

	// upstream gives up early on unscrambled titles rather than scanning
	// the remainder of the source looking for a key that will never appear.
	const noEncryptedLimit = 2000
	var sector [BlockSize]byte
	encryptedSeen := false
	reads := int64(0)
	for block := start; block < dvd.sectorCount; block++ {
		if _, err := dvd.stream.Seek(block*BlockSize, io.SeekStart); err != nil {
			slog.Debug("dvdcss: seek failed while recovering title key", "block", block, "err", err)
			return err
		}
		n, err := dvd.stream.Read(sector[:])
		if n < BlockSize {
			slog.Debug("dvdcss: read did not return full sector while recovering title key", "block", block, "read", n, "err", err)
			break
		}
		if sector[0] != 0 || sector[1] != 0 || sector[2] != 1 {
			break
		}
		if sector[0x14]&0x30 != 0 && sector[0x11] != 0xbb && sector[0x11] != 0xbe && sector[0x11] != 0xbf {
			encryptedSeen = true
			if key, ok := attackPattern(sector[:]); ok {
				dvd.rememberTitleKey(start, key)
				return nil
			}
		}
		reads++
		if reads%0x8000 == 0 {
			slog.Info("dvdcss: still recovering title key", "block", block, "scanned", reads)
		}
		if reads >= noEncryptedLimit && !encryptedSeen {
			slog.Debug("dvdcss: no scrambled sectors found while cracking title key", "start", start, "scanned", reads)
			break
		}
	}
	if encryptedSeen {
		slog.Warn("dvdcss: unable to recover title key", "start", start)
		return fmt.Errorf("dvdcss: unable to recover title key")
	}
	dvd.rememberTitleKey(start, Key{})
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
