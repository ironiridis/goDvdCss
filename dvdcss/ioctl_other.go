//go:build !linux

package dvdcss

import (
	"errors"
	"log/slog"
	"unsafe"
)

var errIOCTLUnimplemented = errors.New("dvdcss: ioctl support is unimplemented on this platform")

func authenticate(fd uintptr) (int, Key, error) {
	slog.Debug("dvdcss: authenticate unimplemented on this platform")
	return 0, Key{}, errIOCTLUnimplemented
}

func (dvd *DVD) loadDiscKey() error {
	slog.Debug("dvdcss: loadDiscKey unimplemented on this platform")
	return errIOCTLUnimplemented
}

func linuxDVDIOCTL(fd uintptr, request uintptr, data unsafe.Pointer) error {
	slog.Debug("dvdcss: linuxDVDIOCTL unimplemented on this platform", "request", request)
	return errIOCTLUnimplemented
}

func ejectTray(fd uintptr) error {
	slog.Debug("dvdcss: ejectTray unimplemented on this platform")
	return errIOCTLUnimplemented
}

func closeTray(fd uintptr) error {
	slog.Debug("dvdcss: closeTray unimplemented on this platform")
	return errIOCTLUnimplemented
}

func readCopyright(fd uintptr, layer int) (int, error) {
	slog.Debug("dvdcss: readCopyright unimplemented on this platform", "layer", layer)
	return 0, errIOCTLUnimplemented
}

func readDiscKey(fd uintptr, agid int) ([]byte, error) {
	slog.Debug("dvdcss: readDiscKey unimplemented on this platform", "agid", agid)
	return nil, errIOCTLUnimplemented
}

func authRequest(fd uintptr, authType byte, data *[16]byte) error {
	slog.Debug("dvdcss: authRequest unimplemented on this platform", "authType", authType)
	return errIOCTLUnimplemented
}

func reportAgid(fd uintptr, agid int) (int, error) {
	slog.Debug("dvdcss: reportAgid unimplemented on this platform", "agid", agid)
	return 0, errIOCTLUnimplemented
}

func sendChallenge(fd uintptr, agid int, challenge [10]byte) error {
	slog.Debug("dvdcss: sendChallenge unimplemented on this platform", "agid", agid)
	return errIOCTLUnimplemented
}

func reportChallenge(fd uintptr, agid int) ([10]byte, error) {
	slog.Debug("dvdcss: reportChallenge unimplemented on this platform", "agid", agid)
	return [10]byte{}, errIOCTLUnimplemented
}

func reportKey1(fd uintptr, agid int) (Key, error) {
	slog.Debug("dvdcss: reportKey1 unimplemented on this platform", "agid", agid)
	return Key{}, errIOCTLUnimplemented
}

func sendKey2(fd uintptr, agid int, key Key) error {
	slog.Debug("dvdcss: sendKey2 unimplemented on this platform", "agid", agid)
	return errIOCTLUnimplemented
}

func reportASF(fd uintptr) (int, error) {
	slog.Debug("dvdcss: reportASF unimplemented on this platform")
	return 0, errIOCTLUnimplemented
}

func readTitleKey(fd uintptr, agid, block int) (Key, error) {
	slog.Debug("dvdcss: readTitleKey unimplemented on this platform", "agid", agid, "block", block)
	return Key{}, errIOCTLUnimplemented
}

func invalidateAGID(fd uintptr, agid int) error {
	slog.Debug("dvdcss: invalidateAGID unimplemented on this platform", "agid", agid)
	return errIOCTLUnimplemented
}

func reportRPC(fd uintptr) (int, int, int, error) {
	slog.Debug("dvdcss: reportRPC unimplemented on this platform")
	return 0, 0, 0, errIOCTLUnimplemented
}
