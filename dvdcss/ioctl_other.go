//go:build !linux

package dvdcss

import (
	"errors"
	"unsafe"
)

var errIOCTLUnimplemented = errors.New("dvdcss: ioctl support is unimplemented on this platform")

func authenticate(fd uintptr) (int, Key, error) {
	return 0, Key{}, errIOCTLUnimplemented
}

func (dvd *DVD) loadDiscKey() error {
	return errIOCTLUnimplemented
}

func linuxDVDIOCTL(fd uintptr, request uintptr, data unsafe.Pointer) error {
	return errIOCTLUnimplemented
}

func readCopyright(fd uintptr, layer int) (int, error) {
	return 0, errIOCTLUnimplemented
}

func readDiscKey(fd uintptr, agid int) ([]byte, error) {
	return nil, errIOCTLUnimplemented
}

func authRequest(fd uintptr, authType byte, data *[16]byte) error {
	return errIOCTLUnimplemented
}

func reportAgid(fd uintptr, agid int) (int, error) {
	return 0, errIOCTLUnimplemented
}

func sendChallenge(fd uintptr, agid int, challenge [10]byte) error {
	return errIOCTLUnimplemented
}

func reportChallenge(fd uintptr, agid int) ([10]byte, error) {
	return [10]byte{}, errIOCTLUnimplemented
}

func reportKey1(fd uintptr, agid int) (Key, error) {
	return Key{}, errIOCTLUnimplemented
}

func sendKey2(fd uintptr, agid int, key Key) error {
	return errIOCTLUnimplemented
}

func reportASF(fd uintptr) (int, error) {
	return 0, errIOCTLUnimplemented
}

func readTitleKey(fd uintptr, agid, block int) (Key, error) {
	return Key{}, errIOCTLUnimplemented
}

func invalidateAGID(fd uintptr, agid int) error {
	return errIOCTLUnimplemented
}

func reportRPC(fd uintptr) (int, int, int, error) {
	return 0, 0, 0, errIOCTLUnimplemented
}
