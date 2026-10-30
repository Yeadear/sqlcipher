package sqlcipher

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestEmptyPlaintextStructure pins the seed's on-disk layout: it must be a valid,
// single-page SQLite database that reserves exactly Reserve bytes per page.
func TestEmptyPlaintextStructure(t *testing.T) {
	// 1024 is the smallest page size whose usable region (1024−80=944) meets
	// SQLite's 480-byte minimum; 512 cannot carry an 80-byte reserve.
	for _, ps := range []int{1024, 4096, 8192, 65536} {
		seed, err := EmptyPlaintext(Params{PageSize: ps})
		if err != nil {
			t.Fatalf("ps=%d: %v", ps, err)
		}
		if len(seed) != ps {
			t.Fatalf("ps=%d: seed is %d bytes, want one page", ps, len(seed))
		}
		if !bytes.HasPrefix(seed, magic) {
			t.Fatalf("ps=%d: missing SQLite magic", ps)
		}
		wantField := ps
		if ps == 65536 {
			wantField = 1 // 65536 is stored as the value 1 (SQLite file format §1.3)
		}
		if got := int(binary.BigEndian.Uint16(seed[16:18])); got != wantField {
			t.Fatalf("ps=%d: header page size field = %d, want %d", ps, got, wantField)
		}
		if seed[20] != Reserve {
			t.Fatalf("ps=%d: reserve byte = %d, want %d", ps, seed[20], Reserve)
		}
		if got := binary.BigEndian.Uint32(seed[28:32]); got != 1 {
			t.Fatalf("ps=%d: in-header page count = %d, want 1", ps, got)
		}
		// header size is trusted only when change counter == version-valid-for
		if !bytes.Equal(seed[24:28], seed[92:96]) {
			t.Fatalf("ps=%d: change counter != version-valid-for; header size not trusted", ps)
		}
		if seed[100] != 0x0D {
			t.Fatalf("ps=%d: page-1 b-tree type = %#x, want 0x0d (leaf table)", ps, seed[100])
		}
		if got := int(binary.BigEndian.Uint16(seed[103:105])); got != 0 {
			t.Fatalf("ps=%d: cell count = %d, want 0", ps, got)
		}
		if got := int(binary.BigEndian.Uint16(seed[105:107])); got != ps-Reserve {
			t.Fatalf("ps=%d: cell content area start = %d, want usable %d", ps, got, ps-Reserve)
		}
	}
}

// TestEmptyPlaintextEncryptsAndRoundTrips proves the seed is exactly what the
// codec needs: EncryptFile accepts it (its reserve is present) and produces
// ciphertext with no plaintext header, and DecryptFile restores a plaintext
// SQLite database whose reserve the header still records. This is the pure-Go
// half of the new-database path; the modernc-write + C-read half lives in parity.
func TestEmptyPlaintextEncryptsAndRoundTrips(t *testing.T) {
	seed, err := EmptyPlaintext(Params{})
	if err != nil {
		t.Fatal(err)
	}

	var enc bytes.Buffer
	if err := EncryptFile(&enc, bytes.NewReader(seed), RawKey(testKey), testSalt, Params{}); err != nil {
		t.Fatalf("EncryptFile rejected the seed: %v", err)
	}
	if bytes.HasPrefix(enc.Bytes(), magic) {
		t.Fatal("encrypted seed has a plaintext SQLite header")
	}
	if !bytes.Equal(enc.Bytes()[:SaltSize], testSalt) {
		t.Fatal("encrypted page 1 does not begin with the salt")
	}

	var dec bytes.Buffer
	if err := DecryptFile(&dec, bytes.NewReader(enc.Bytes()), RawKey(testKey), Params{}); err != nil {
		t.Fatalf("DecryptFile: %v", err)
	}
	if !bytes.HasPrefix(dec.Bytes(), magic) {
		t.Fatal("decrypted seed did not restore the SQLite magic")
	}
	if dec.Bytes()[20] != Reserve {
		t.Fatalf("decrypted reserve byte = %d, want %d", dec.Bytes()[20], Reserve)
	}
}

// TestEmptyPlaintextBadPageSize rejects a non-power-of-two page size and a page
// size too small to carry the reserve.
func TestEmptyPlaintextBadPageSize(t *testing.T) {
	if _, err := EmptyPlaintext(Params{PageSize: 5000}); err == nil {
		t.Fatal("accepted a non-power-of-two page size")
	}
	if _, err := EmptyPlaintext(Params{PageSize: 512}); err == nil {
		t.Fatal("accepted a 512-byte page (usable 432 < SQLite's 480 minimum) with an 80-byte reserve")
	}
}
