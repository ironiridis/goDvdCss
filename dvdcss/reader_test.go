package dvdcss

import "testing"

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
