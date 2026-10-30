package sqlcipher

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// DecryptFile decrypts a whole database, writing a plaintext SQLite database that
// any SQLite build can open without a key. The salt is read from the source's
// page 1.
//
// The result keeps the source's per-page Reserve trailer — SQLite records the
// reserve in byte 20 of the header, so the plaintext database describes itself and
// stays a lossless round-trip back through EncryptFile.
func DecryptFile(dst io.Writer, src io.Reader, k Key, p Params) error {
	return convert(dst, src, k, p, nil, (*Codec).Decrypt)
}

// EncryptFile encrypts a whole plaintext SQLite database.
//
// The source must already reserve Reserve bytes per page (header byte 20), which
// is what a database DecryptFile produced does; otherwise there is no room for the
// IV and tag and this returns an error rather than truncating data. A nil salt
// draws a fresh random one, which is what a new database wants; pass a salt only
// to rewrite a database under its existing one.
func EncryptFile(dst io.Writer, src io.Reader, k Key, salt []byte, p Params) error {
	if salt == nil {
		salt = make([]byte, SaltSize)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return fmt.Errorf("sqlcipher: new salt: %w", err)
		}
	}
	return convert(dst, src, k, p, salt, (*Codec).Encrypt)
}

// convert streams src page by page through op. salt is nil when it must be read
// from the source's page 1 (decrypting) and set when it is chosen (encrypting).
func convert(dst io.Writer, src io.Reader, k Key, p Params, salt []byte, op func(*Codec, uint32, []byte) ([]byte, error)) error {
	page := make([]byte, p.pageSize())
	var c *Codec

	for pgno := uint32(1); ; pgno++ {
		n, err := io.ReadFull(src, page)
		if errors.Is(err, io.EOF) && pgno > 1 {
			return nil // clean end of file: whole number of pages
		}
		if err != nil {
			return fmt.Errorf("sqlcipher: read page %d: %w", pgno, err)
		}
		if n != len(page) {
			return fmt.Errorf("sqlcipher: page %d is %d bytes, want %d", pgno, n, len(page))
		}

		if pgno == 1 {
			if salt == nil {
				// Decrypting: the database carries its own salt in the clear.
				if salt, err = FileSalt(page); err != nil {
					return err
				}
		} else if !hasReserve(page, p.reserve()) {
			return fmt.Errorf("sqlcipher: source database reserves %d bytes per page, need %d "+
				"(SQLite header byte 20): it cannot be encrypted without losing data", page[20], p.reserve())
		}
			if c, err = NewCodec(k, salt, p); err != nil {
				return err
			}
		}

		out, err := op(c, pgno, page)
		if err != nil {
			return err
		}
		if _, err := dst.Write(out); err != nil {
			return fmt.Errorf("sqlcipher: write page %d: %w", pgno, err)
		}
	}
}

// hasReserve reports whether a plaintext page 1 declares the given reserve. Byte
// 20 of the SQLite header is the per-page unused reserve.
func hasReserve(page1 []byte, want int) bool { return len(page1) > 20 && int(page1[20]) == want }
