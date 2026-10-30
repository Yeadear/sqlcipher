package sqlcipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"
)

// Decrypt decrypts one on-disk page and returns its plaintext. page must be
// exactly PageSize bytes; the result is a fresh slice of the same length.
//
// The page is authenticated before it is decrypted, so a wrong key returns ErrKey
// rather than plausible-looking garbage. pgno is 1-based, as SQLite numbers pages.
//
// Decrypting page 1 restores SQLite's "SQLite format 3\x00" magic over the salt,
// which is what SQLite's pager expects to read. The reserve trailer is carried
// through unchanged; SQLite ignores it.
func (c *Codec) Decrypt(pgno uint32, page []byte) ([]byte, error) {
	body, size, err := c.split(pgno, page)
	if err != nil {
		return nil, err
	}
	off := offset(pgno)
	iv := body[size : size+IVSize]
	hmacStart := size + IVSize

	if subtle.ConstantTimeCompare(body[hmacStart:hmacStart+c.hmacSize()], c.pageMAC(pgno, body[:hmacStart])) != 1 {
		return nil, fmt.Errorf("page %d: %w", pgno, ErrKey)
	}

	out := make([]byte, c.pageSize)
	if pgno == 1 {
		copy(out, magic)
	}
	copy(out[off+size:], body[size:])
	cipher.NewCBCDecrypter(c.block(), iv).CryptBlocks(out[off:off+size], body[:size])
	return out, nil
}

// Encrypt encrypts one plaintext page and returns the bytes to store on disk.
// page must be exactly PageSize bytes, of which only the first PageSize-Reserve
// carry data — SQLite guarantees that by reserving Reserve bytes per page.
//
// Every call draws a fresh IV, so encrypting the same page twice yields different
// ciphertext. Encrypting page 1 writes the database salt over SQLite's magic.
func (c *Codec) Encrypt(pgno uint32, page []byte) ([]byte, error) {
	_, size, err := c.split(pgno, page)
	if err != nil {
		return nil, err
	}
	off := offset(pgno)

	out := make([]byte, c.pageSize)
	if pgno == 1 {
		copy(out, c.salt)
	}
	// Fill the whole trailer with random bytes and then lay the tag over it, so
	// any reserve larger than IV||HMAC carries random padding rather than zeros.
	if _, err := io.ReadFull(c.random(), out[off+size:]); err != nil {
		return nil, fmt.Errorf("sqlcipher: page %d: read iv: %w", pgno, err)
	}
	iv := out[off+size : off+size+IVSize]

	cipher.NewCBCEncrypter(c.block(), iv).CryptBlocks(out[off:off+size], page[off:off+size])
	copy(out[off+size+IVSize:], c.pageMAC(pgno, out[off:off+size+IVSize]))
	return out, nil
}

// split validates a page and returns its encrypted region (ciphertext||IV||HMAC)
// along with the ciphertext length.
func (c *Codec) split(pgno uint32, page []byte) (body []byte, size int, err error) {
	if pgno == 0 {
		return nil, 0, fmt.Errorf("sqlcipher: page numbers are 1-based, got %d", pgno)
	}
	if len(page) != c.pageSize {
		return nil, 0, fmt.Errorf("sqlcipher: page %d must be %d bytes, got %d", pgno, c.pageSize, len(page))
	}
	body = page[offset(pgno):]
	size = len(body) - c.reserve()
	if size <= 0 || size%blockSize != 0 {
		return nil, 0, fmt.Errorf("sqlcipher: page size %d leaves no whole-block payload for page %d", c.pageSize, pgno)
	}
	return body, size, nil
}

func (c *Codec) block() cipher.Block {
	b, err := aes.NewCipher(c.key)
	if err != nil {
		panic("sqlcipher: " + err.Error()) // unreachable: NewCodec fixes the key at KeySize
	}
	return b
}

// random is the IV source. Tests replace it to pin IVs for golden vectors; it is
// never settable from outside the package, so callers cannot weaken it.
func (c *Codec) random() io.Reader {
	if c.rand != nil {
		return c.rand
	}
	return rand.Reader
}
