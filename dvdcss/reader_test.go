package dvdcss

import (
	"bytes"
	"io"
	"testing"
)

type shortReadSeeker struct {
	n        int
	position int64
	reads    int
}

func (stream *shortReadSeeker) Read(buffer []byte) (int, error) {
	stream.reads++
	return stream.n, nil
}

func (stream *shortReadSeeker) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		stream.position = offset
	case io.SeekCurrent:
		stream.position += offset
	case io.SeekEnd:
		stream.position = BlockSize + offset
	}
	return stream.position, nil
}

type countingReadSeeker struct {
	*bytes.Reader
	reads int
}

func (stream *countingReadSeeker) Read(buffer []byte) (int, error) {
	stream.reads++
	return stream.Reader.Read(buffer)
}

func TestEjectRequiresFileDescriptor(t *testing.T) {
	dvd := New(nil)
	if err := dvd.Eject(false); err == nil {
		t.Fatal("Eject succeeded without a file descriptor")
	}
}

func TestTitleKeyCacheSelectsByBlock(t *testing.T) {
	dvd := New(nil)
	first := Key{0x01, 0x02, 0x03, 0x04, 0x05}
	second := Key{0x06, 0x07, 0x08, 0x09, 0x0a}
	dvd.rememberTitleKey(100, first)
	dvd.rememberTitleKey(200, second)

	if !dvd.tryTitleKey(100) || dvd.titleKey != first {
		t.Fatalf("block 100 selected title key %v, want %v", dvd.titleKey, first)
	}
	if !dvd.tryTitleKey(200) || dvd.titleKey != second {
		t.Fatalf("block 200 selected title key %v, want %v", dvd.titleKey, second)
	}
	if dvd.tryTitleKey(300) {
		t.Fatal("uncached block unexpectedly has a title key")
	}
}

func TestEnsureTitleKeyStopsOnIncompleteSector(t *testing.T) {
	tests := []struct {
		name     string
		readSize int
	}{
		{name: "zero bytes", readSize: 0},
		{name: "partial sector", readSize: BlockSize - 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stream := &shortReadSeeker{n: test.readSize}
			dvd := New(stream)

			if err := dvd.ensureTitleKey(0); err != nil {
				t.Fatalf("ensureTitleKey returned %v", err)
			}
			if stream.reads != 1 {
				t.Fatalf("Read called %d times, want 1", stream.reads)
			}
			if !dvd.titleKnown || dvd.titleKey != (Key{}) {
				t.Fatalf("title key state = known:%t key:%v, want known zero key", dvd.titleKnown, dvd.titleKey)
			}
		})
	}
}

func TestNewRecordsCompleteSectorCountAndPreservesPosition(t *testing.T) {
	stream := bytes.NewReader(make([]byte, 2*BlockSize+1))
	if _, err := stream.Seek(BlockSize, io.SeekStart); err != nil {
		t.Fatal(err)
	}

	dvd := New(stream)
	if dvd.sizeErr != nil {
		t.Fatalf("New recorded source size error: %v", dvd.sizeErr)
	}
	if dvd.sectorCount != 2 {
		t.Fatalf("sector count = %d, want 2", dvd.sectorCount)
	}
	position, err := stream.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Fatal(err)
	}
	if position != BlockSize {
		t.Fatalf("stream position = %d, want %d", position, BlockSize)
	}
}

func TestEnsureTitleKeyStopsAtSourceEnd(t *testing.T) {
	data := make([]byte, 2*BlockSize)
	for block := range 2 {
		sector := data[block*BlockSize : (block+1)*BlockSize]
		sector[2] = 1
		for index := 3; index < 0x80; index++ {
			sector[index] = byte(index)
		}
		sector[0x14] = 0x20
	}
	if _, ok := attackPattern(data[:BlockSize]); ok {
		t.Fatal("test sector unexpectedly has a recoverable title key pattern")
	}

	stream := &countingReadSeeker{Reader: bytes.NewReader(data)}
	dvd := New(stream)
	if err := dvd.ensureTitleKey(0); err == nil {
		t.Fatal("ensureTitleKey succeeded without a recoverable key")
	}
	if stream.reads != 2 {
		t.Fatalf("Read called %d times, want 2", stream.reads)
	}
}

var _ io.ReadSeeker = (*shortReadSeeker)(nil)
