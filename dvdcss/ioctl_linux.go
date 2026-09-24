//go:build linux

package dvdcss

import (
	"syscall"
	"unsafe"
)

const (
	dvdReadStruct = 0x5390
	dvdAuth       = 0x5392

	dvdStructCopyright = 1
	dvdStructDiscKey   = 2

	dvdLUSendAGID        = 0
	dvdHostSendChallenge = 1
	dvdLUSendKey1        = 2
	dvdLUSendChallenge   = 3
	dvdHostSendKey2      = 4
	dvdLUSendTitleKey    = 5
	dvdLUSendASF         = 8
	dvdInvalidateAGID    = 6
	dvdLUSendRPCState    = 10
)

func linuxDVDIOCTL(fd int, request uintptr, data unsafe.Pointer) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), request, uintptr(data))
	if errno != 0 {
		return errno
	}
	return nil
}

func readCopyright(fd, layer int) (int, error) {
	var data [2056]byte
	data[0] = dvdStructCopyright
	data[1] = byte(layer)
	if err := linuxDVDIOCTL(fd, dvdReadStruct, unsafe.Pointer(&data[0])); err != nil {
		return 0, err
	}
	return int(data[2]), nil
}

func readDiscKey(fd, agid int) ([]byte, error) {
	var data [2056]byte
	data[0] = dvdStructDiscKey
	data[1] = byte(agid & 3)
	if err := linuxDVDIOCTL(fd, dvdReadStruct, unsafe.Pointer(&data[0])); err != nil {
		return nil, err
	}
	key := make([]byte, 2048)
	copy(key, data[4:])
	return key, nil
}

func authRequest(fd int, authType byte, data *[16]byte) error {
	data[0] = authType
	return linuxDVDIOCTL(fd, dvdAuth, unsafe.Pointer(&data[0]))
}

func reportAgid(fd, agid int) (int, error) {
	var data [16]byte
	data[1] = byte(agid & 3)
	if err := authRequest(fd, dvdLUSendAGID, &data); err != nil {
		return 0, err
	}
	return int(data[1] & 3), nil
}

func sendChallenge(fd, agid int, challenge [10]byte) error {
	var data [16]byte
	data[1] = byte(agid & 3)
	copy(data[2:], challenge[:])
	return authRequest(fd, dvdHostSendChallenge, &data)
}

func reportChallenge(fd, agid int) ([10]byte, error) {
	var data [16]byte
	data[1] = byte(agid & 3)
	if err := authRequest(fd, dvdLUSendChallenge, &data); err != nil {
		return [10]byte{}, err
	}
	var challenge [10]byte
	copy(challenge[:], data[2:12])
	return challenge, nil
}

func reportKey1(fd, agid int) (Key, error) {
	var data [16]byte
	data[1] = byte(agid & 3)
	if err := authRequest(fd, dvdLUSendKey1, &data); err != nil {
		return Key{}, err
	}
	var key Key
	copy(key[:], data[2:7])
	return key, nil
}

func sendKey2(fd, agid int, key Key) error {
	var data [16]byte
	data[1] = byte(agid & 3)
	copy(data[2:], key[:])
	return authRequest(fd, dvdHostSendKey2, &data)
}

func reportASF(fd int) (int, error) {
	var data [16]byte
	if err := authRequest(fd, dvdLUSendASF, &data); err != nil {
		return 0, err
	}
	return int(data[1] & 1), nil
}

func readTitleKey(fd, agid, block int) (Key, error) {
	var data [16]byte
	data[1] = byte(agid & 3)
	*(*int32)(unsafe.Pointer(&data[8])) = int32(block)
	if err := authRequest(fd, dvdLUSendTitleKey, &data); err != nil {
		return Key{}, err
	}
	var key Key
	copy(key[:], data[2:7])
	return key, nil
}

func invalidateAGID(fd, agid int) error {
	var data [16]byte
	data[1] = byte(agid & 3)
	return authRequest(fd, dvdInvalidateAGID, &data)
}

func reportRPC(fd int) (int, int, int, error) {
	var data [16]byte
	if err := authRequest(fd, dvdLUSendRPCState, &data); err != nil {
		return 0, 0, 0, err
	}
	return int(data[0] & 3), int(data[1]), int(data[2]), nil
}
