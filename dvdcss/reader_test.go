package dvdcss

import (
	"io"
	"testing"
)

type shortReadSeeker struct {
	n     int
	reads int
}

func (stream *shortReadSeeker) Read(buffer []byte) (int, error) {
	stream.reads++
	return stream.n, nil
}

func (stream *shortReadSeeker) Seek(_ int64, _ int) (int64, error) {
	return 0, nil
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

var _ io.ReadSeeker = (*shortReadSeeker)(nil)
