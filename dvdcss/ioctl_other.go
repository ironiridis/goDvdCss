//go:build !linux

package dvdcss

import (
	"errors"
	"unsafe"
)

var errIOCTLUnimplemented = errors.New("dvdcss: ioctl support is unimplemented on this platform")

func authenticate(fd int) (int, Key, error) {
	return 0, Key{}, errIOCTLUnimplemented
}

func (dvd *DVD) loadDiscKey() error {
	return errIOCTLUnimplemented
}

func linuxDVDIOCTL(fd int, request uintptr, data unsafe.Pointer) error {
	return errIOCTLUnimplemented
}

func readCopyright(fd, layer int) (int, error) {
	return 0, errIOCTLUnimplemented
}

func readDiscKey(fd, agid int) ([]byte, error) {
	return nil, errIOCTLUnimplemented
}

func authRequest(fd int, authType byte, data *[16]byte) error {
	return errIOCTLUnimplemented
}

func reportAgid(fd, agid int) (int, error) {
	return 0, errIOCTLUnimplemented
}

func sendChallenge(fd, agid int, challenge [10]byte) error {
	return errIOCTLUnimplemented
}

func reportChallenge(fd, agid int) ([10]byte, error) {
	return [10]byte{}, errIOCTLUnimplemented
}

func reportKey1(fd, agid int) (Key, error) {
	return Key{}, errIOCTLUnimplemented
}

func sendKey2(fd, agid int, key Key) error {
	return errIOCTLUnimplemented
}

func reportASF(fd int) (int, error) {
	return 0, errIOCTLUnimplemented
}

func readTitleKey(fd, agid, block int) (Key, error) {
	return Key{}, errIOCTLUnimplemented
}

func invalidateAGID(fd, agid int) error {
	return errIOCTLUnimplemented
}

func reportRPC(fd int) (int, int, int, error) {
	return 0, 0, 0, errIOCTLUnimplemented
}
