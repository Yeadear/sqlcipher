package sqlcipher

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

// testKey and testSalt are fixed so every vector below is reproducible. testKey
// is also the key testdata/c-4.5.6.db was written under by the real C library.
var (
	testKey  = mustHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	testSalt = mustHex("000102030405060708090a0b0c0d0e0f")
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// fixed is a deterministic byte source, standing in for crypto/rand so a golden
// vector can pin the exact ciphertext of a page.
type fixed byte

func (f fixed) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(f)
	}
	return len(p), nil
}

func codec(t *testing.T) *Codec {
	t.Helper()
	c, err := NewCodec(RawKey(testKey), testSalt, Params{})
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	return c
}

// TestKeyDerivation pins the KDF. These are the two keys SQLCipher derives; if
// either changes, every database written before the change becomes unreadable.
func TestKeyDerivation(t *testing.T) {
	t.Run("raw key is used verbatim", func(t *testing.T) {
		c := codec(t)
		if !bytes.Equal(c.key, testKey) {
			t.Errorf("raw keying must skip the KDF\n got %x\nwant %x", c.key, testKey)
		}
	})

	t.Run("page-authentication key", func(t *testing.T) {
		// PBKDF2-HMAC-SHA512(key, salt^0x3a, 2 iterations, 32 bytes).
		const want = "601364baed0dde5a2d291ede302ae7e0540a85b57a281a0d19c344b7d4f382ce"
		got := hex.EncodeToString(codec(t).mac)
		if got != want {
			t.Errorf("page-authentication key changed\n got %s\nwant %s", got, want)
		}
	})

	t.Run("passphrase keying", func(t *testing.T) {
		c, err := NewCodec(Passphrase("correct horse battery staple"), testSalt, Params{})
		if err != nil {
			t.Fatalf("NewCodec: %v", err)
		}
		const want = "2c6ee106931bbdc6ea7e33497f04526ccbe4fb541379d36a506a65eabed0d8e2"
		if got := hex.EncodeToString(c.key); got != want {
			t.Errorf("passphrase key changed\n got %s\nwant %s", got, want)
		}
	})

	t.Run("the two keys are distinct", func(t *testing.T) {
		c := codec(t)
		if bytes.Equal(c.key, c.mac) {
			t.Fatal("encryption and authentication keys must not be equal")
		}
	})
}

// TestGoldenPage pins the whole on-disk page layout for a fixed key, salt, IV and
// plaintext. It is the vector that stops a refactor from silently changing the
// format.
func TestGoldenPage(t *testing.T) {
	c := codec(t)
	c.rand = fixed(0xAB) // pins the IV, which crypto/rand would otherwise vary

	page := make([]byte, DefaultPageSize)
	copy(page, magic)
	copy(page[100:], "golden")

	out, err := c.Encrypt(2, page)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	const want = "a33e43ee2bbd44de" // sha256(page)[:8], hex
	if got := digest(out); got != want {
		t.Errorf("page 2 ciphertext changed\n got %s\nwant %s", got, want)
	}
	if iv := out[DefaultPageSize-Reserve : DefaultPageSize-Reserve+IVSize]; !bytes.Equal(iv, bytes.Repeat([]byte{0xAB}, IVSize)) {
		t.Errorf("IV must be stored at the head of the reserve, got %x", iv)
	}
}

// TestPage1KeepsSaltInTheClear checks the one page that is special.
func TestPage1KeepsSaltInTheClear(t *testing.T) {
	c := codec(t)
	page := make([]byte, DefaultPageSize)
	copy(page, magic)
	page[20] = Reserve

	out, err := c.Encrypt(1, page)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !bytes.Equal(out[:SaltSize], testSalt) {
		t.Errorf("page 1 must store the salt in the clear, got %x", out[:SaltSize])
	}
	if bytes.HasPrefix(out, magic) {
		t.Error("page 1 must not leave SQLite's magic on disk")
	}

	back, err := c.Decrypt(1, out)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.HasPrefix(back, magic) {
		t.Errorf("decrypting page 1 must restore SQLite's magic, got %q", back[:SaltSize])
	}
	if !bytes.Equal(back[:DefaultPageSize-Reserve], page[:DefaultPageSize-Reserve]) {
		t.Error("page 1 round-trip lost data")
	}
}

// TestRoundTrip covers the ordinary pages.
func TestRoundTrip(t *testing.T) {
	c := codec(t)
	for _, pgno := range []uint32{1, 2, 3, 1000, 4294967295} {
		page := make([]byte, DefaultPageSize)
		for i := range page[:DefaultPageSize-Reserve] {
			page[i] = byte(i * int(pgno))
		}
		if pgno == 1 {
			copy(page, magic)
		}
		enc, err := c.Encrypt(pgno, page)
		if err != nil {
			t.Fatalf("page %d: Encrypt: %v", pgno, err)
		}
		if bytes.Equal(enc[offset(pgno):DefaultPageSize-Reserve], page[offset(pgno):DefaultPageSize-Reserve]) {
			t.Fatalf("page %d was not encrypted", pgno)
		}
		back, err := c.Decrypt(pgno, enc)
		if err != nil {
			t.Fatalf("page %d: Decrypt: %v", pgno, err)
		}
		want := page[offset(pgno) : DefaultPageSize-Reserve]
		if !bytes.Equal(back[offset(pgno):DefaultPageSize-Reserve], want) {
			t.Fatalf("page %d round-trip corrupted data", pgno)
		}
	}
}

// TestFreshIVEveryWrite: CBC reuses of an IV under one key leak plaintext
// relationships, so the same page encrypted twice must differ.
func TestFreshIVEveryWrite(t *testing.T) {
	c := codec(t)
	page := make([]byte, DefaultPageSize)
	a, err := c.Encrypt(2, page)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Encrypt(2, page)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two writes of the same page produced the same bytes: the IV is not fresh")
	}
}

// TestFailsClosed is the property the whole design rests on: anything other than
// the right key over intact bytes must error, never return plaintext.
func TestFailsClosed(t *testing.T) {
	c := codec(t)
	page := make([]byte, DefaultPageSize)
	copy(page[100:], "secret")
	enc, err := c.Encrypt(7, page)
	if err != nil {
		t.Fatal(err)
	}

	tamper := func(name string, mutate func([]byte) (*Codec, uint32, []byte)) {
		t.Run(name, func(t *testing.T) {
			bad := append([]byte(nil), enc...)
			cc, pgno, in := mutate(bad)
			out, err := cc.Decrypt(pgno, in)
			if err == nil {
				t.Fatalf("FAIL OPEN: returned %d bytes of plaintext instead of an error", len(out))
			}
			if !errors.Is(err, ErrKey) {
				t.Fatalf("want ErrKey, got %v", err)
			}
			if out != nil {
				t.Fatal("must not return data alongside the error")
			}
		})
	}

	tamper("wrong key", func(b []byte) (*Codec, uint32, []byte) {
		k := append([]byte(nil), testKey...)
		k[31] ^= 1
		cc, err := NewCodec(RawKey(k), testSalt, Params{})
		if err != nil {
			t.Fatal(err)
		}
		return cc, 7, b
	})
	tamper("wrong salt", func(b []byte) (*Codec, uint32, []byte) {
		s := append([]byte(nil), testSalt...)
		s[0] ^= 1
		cc, err := NewCodec(RawKey(testKey), s, Params{})
		if err != nil {
			t.Fatal(err)
		}
		return cc, 7, b
	})
	tamper("flipped ciphertext bit", func(b []byte) (*Codec, uint32, []byte) {
		b[64] ^= 1
		return c, 7, b
	})
	tamper("flipped IV bit", func(b []byte) (*Codec, uint32, []byte) {
		b[DefaultPageSize-Reserve] ^= 1
		return c, 7, b
	})
	tamper("flipped tag bit", func(b []byte) (*Codec, uint32, []byte) {
		b[DefaultPageSize-1] ^= 1
		return c, 7, b
	})
	// The page number is authenticated, so a page cannot be replayed at another
	// offset in the file even though it is otherwise a valid page.
	tamper("page replayed at another page number", func(b []byte) (*Codec, uint32, []byte) {
		return c, 8, b
	})
}

// TestDecryptsDatabaseWrittenByC is the byte-compatibility gate, pinned as a
// regression: testdata/c-4.5.6.db was written by the real C libsqlcipher 4.5.6.
// If this ever fails, the port has drifted from the format and every database in
// production has become unreadable.
func TestDecryptsDatabaseWrittenByC(t *testing.T) {
	enc, err := os.ReadFile("testdata/c-4.5.6.db")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.HasPrefix(enc, magic) {
		t.Fatal("fixture is not encrypted")
	}

	var plain bytes.Buffer
	if err := DecryptFile(&plain, bytes.NewReader(enc), RawKey(testKey), Params{}); err != nil {
		t.Fatalf("failed to decrypt a database the C library wrote: %v", err)
	}
	pt := plain.Bytes()

	if len(pt) != len(enc) {
		t.Errorf("decrypt changed the file length: %d -> %d", len(enc), len(pt))
	}
	if !bytes.HasPrefix(pt, magic) {
		t.Fatalf("decrypted page 1 is not a SQLite header: %q", pt[:16])
	}
	if pt[20] != Reserve {
		t.Errorf("C wrote reserve %d, this port expects %d", pt[20], Reserve)
	}
	if got := int(pt[16])<<8 | int(pt[17])<<16; got != DefaultPageSize {
		t.Errorf("page size = %d, want %d", got, DefaultPageSize)
	}
	for _, want := range []string{"hello-from-c", "ledger-row-two", "idx_t_v"} {
		if !bytes.Contains(pt, []byte(want)) {
			t.Errorf("decrypted database is missing %q", want)
		}
	}
}

// TestReencryptMatchesC checks the other direction at the file level: re-encrypt
// the decrypted fixture under its own salt and the result must decrypt back to
// exactly the same plaintext. (That the C library itself reads Go-written
// databases is proven by the parity harness, which needs libsqlcipher present.)
func TestReencryptMatchesC(t *testing.T) {
	enc, err := os.ReadFile("testdata/c-4.5.6.db")
	if err != nil {
		t.Fatal(err)
	}
	salt, err := FileSalt(enc)
	if err != nil {
		t.Fatal(err)
	}

	var plain, again, back bytes.Buffer
	if err := DecryptFile(&plain, bytes.NewReader(enc), RawKey(testKey), Params{}); err != nil {
		t.Fatal(err)
	}
	if err := EncryptFile(&again, bytes.NewReader(plain.Bytes()), RawKey(testKey), salt, Params{}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again.Bytes()[:SaltSize], salt) {
		t.Error("re-encrypting under an explicit salt must keep that salt")
	}
	if err := DecryptFile(&back, bytes.NewReader(again.Bytes()), RawKey(testKey), Params{}); err != nil {
		t.Fatal(err)
	}
	// The reserve holds the IV, which is fresh on every write, so the trailer is
	// expected to differ. The usable bytes -- the database itself -- must not.
	if err := sameData(plain.Bytes(), back.Bytes()); err != nil {
		t.Fatalf("decrypt -> encrypt -> decrypt lost data: %v", err)
	}
}

// TestEncryptFileRefusesUnreservedDatabase: a plaintext database with no reserve
// has no room for the IV and tag. Encrypting it would silently destroy the last
// Reserve bytes of every page, so it must be refused.
func TestEncryptFileRefusesUnreservedDatabase(t *testing.T) {
	page := make([]byte, DefaultPageSize)
	copy(page, magic)
	page[16], page[17] = 0x10, 0x00 // page size 4096
	page[20] = 0                    // no reserve

	err := EncryptFile(io.Discard, bytes.NewReader(page), RawKey(testKey), testSalt, Params{})
	if err == nil {
		t.Fatal("FAIL OPEN: encrypted a database that has no room for the page trailer")
	}
	if !strings.Contains(err.Error(), "reserve") {
		t.Errorf("error should name the reserve, got: %v", err)
	}
}

func TestRejectsBadInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		fn   func() error
	}{
		{"short salt", func() error { _, err := NewCodec(RawKey(testKey), testSalt[:8], Params{}); return err }},
		{"short key", func() error { _, err := NewCodec(RawKey(testKey[:16]), testSalt, Params{}); return err }},
		{"no key material", func() error { _, err := NewCodec(Key{}, testSalt, Params{}); return err }},
		{"page size not a power of two", func() error {
			_, err := NewCodec(RawKey(testKey), testSalt, Params{PageSize: 5000})
			return err
		}},
		{"page 0", func() error { _, err := codec(t).Decrypt(0, make([]byte, DefaultPageSize)); return err }},
		{"short page", func() error { _, err := codec(t).Decrypt(1, make([]byte, 100)); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.fn(); err == nil {
				t.Fatal("want error, got nil")
			}
		})
	}
}

// digest identifies a page by the first 8 bytes of its SHA-256, which is enough
// to pin the bytes without printing 4KiB of hex in a diff.
func digest(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

// sameData compares two plaintext databases over the bytes SQLite actually uses,
// ignoring each page's reserve trailer.
func sameData(a, b []byte) error {
	if len(a) != len(b) {
		return fmt.Errorf("length %d != %d", len(a), len(b))
	}
	for off := 0; off < len(a); off += DefaultPageSize {
		end := off + DefaultPageSize - Reserve
		if !bytes.Equal(a[off:end], b[off:end]) {
			return fmt.Errorf("page %d differs", off/DefaultPageSize+1)
		}
	}
	return nil
}

// TestDecryptsPassphraseDatabaseWrittenByC cross-verifies the passphrase KDF
// against the C library: this fixture was keyed by libsqlcipher 4.5.6 with a
// passphrase, so decrypting it proves PBKDF2-HMAC-SHA512 at 256000 iterations
// agrees byte for byte. Without it, the passphrase vector above would only pin
// this port to itself.
func TestDecryptsPassphraseDatabaseWrittenByC(t *testing.T) {
	enc, err := os.ReadFile("testdata/c-4.5.6-passphrase.db")
	if err != nil {
		t.Fatal(err)
	}
	var plain bytes.Buffer
	if err := DecryptFile(&plain, bytes.NewReader(enc), Passphrase("correct horse battery staple"), Params{}); err != nil {
		t.Fatalf("failed to decrypt a passphrase-keyed database the C library wrote: %v", err)
	}
	if !bytes.HasPrefix(plain.Bytes(), magic) {
		t.Fatal("decrypted page 1 is not a SQLite header")
	}
	if !bytes.Contains(plain.Bytes(), []byte("passphrase-keyed-by-c")) {
		t.Error("decrypted database is missing the row the C library inserted")
	}
}

// TestWrongPassphraseFailsClosed guards the KDF path too.
func TestWrongPassphraseFailsClosed(t *testing.T) {
	enc, err := os.ReadFile("testdata/c-4.5.6-passphrase.db")
	if err != nil {
		t.Fatal(err)
	}
	err = DecryptFile(io.Discard, bytes.NewReader(enc), Passphrase("correct horse battery stapl"), Params{})
	if err == nil {
		t.Fatal("FAIL OPEN: a wrong passphrase decrypted the database")
	}
	if !errors.Is(err, ErrKey) {
		t.Fatalf("want ErrKey, got %v", err)
	}
}
