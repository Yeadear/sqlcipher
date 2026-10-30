package sqlcipher

import (
	"encoding/binary"
	"fmt"
)

// EmptyPlaintext returns the bytes of a minimal empty SQLite database — one page,
// an empty sqlite_master, no tables — that reserves Reserve (80) bytes per page.
//
// It is the plaintext seed a NEW encrypted database is built from. EncryptFile
// requires its source to already reserve Reserve bytes per page (header byte 20),
// because the per-page IV+HMAC trailer is written into that reserve; a database
// that does not reserve it cannot be encrypted without losing data. A plaintext
// SQLite engine cannot be asked to create a database with a non-zero reserve
// through SQL (the reserve is set via SQLITE_FCNTL_RESERVE_BYTES, not a PRAGMA),
// so a pure-Go writer that wants a fresh encrypted database starts from this seed:
// open it, write the schema (SQLite honours the reserve recorded in the header, so
// every page it writes leaves room for the trailer), then EncryptFile the result.
//
// The layout follows the SQLite file format
// (https://www.sqlite.org/fileformat.html §1.3 "Database Header", §1.6 "B-tree
// Pages"): a single leaf table b-tree page holding an empty sqlite_master, with
// byte 20 set to Reserve and the cell-content-area pointer at the usable-size
// boundary (pageSize − Reserve). The in-header page count is 1 and the file is
// exactly one page, so an engine trusts the header size (the change counter equals
// the version-valid-for field). p.PageSize selects the page size (0 ⇒
// DefaultPageSize); p.Iter is unused here.
func EmptyPlaintext(p Params) ([]byte, error) {
	ps := p.pageSize()
	if ps < 512 || ps > 65536 || ps&(ps-1) != 0 {
		return nil, fmt.Errorf("sqlcipher: page size %d is not a power of two in [512,65536]", ps)
	}
	if ps-Reserve < 480 {
		// SQLite requires the usable size (pageSize − reserve) to be at least 480
		// bytes, so a 512-byte page cannot carry an 80-byte reserve (432 usable):
		// the smallest page size that can be a SQLCipher database is 1024.
		return nil, fmt.Errorf("sqlcipher: page size %d with reserve %d leaves %d usable, below SQLite's 480-byte minimum", ps, Reserve, ps-Reserve)
	}

	page := make([]byte, ps)

	// ── database header (bytes 0..99) ──
	copy(page[0:16], magic) // "SQLite format 3\0"
	// Page size is a big-endian uint16, EXCEPT 65536 is stored as the value 1
	// (it does not fit in two bytes) — SQLite file format §1.3.
	if ps == 65536 {
		binary.BigEndian.PutUint16(page[16:18], 1)
	} else {
		binary.BigEndian.PutUint16(page[16:18], uint16(ps))
	}
	page[18] = 1                               // file format write version (rollback journal)
	page[19] = 1                               // file format read version
	page[20] = Reserve                         // reserved bytes per page — the load-bearing field
	page[21] = 64                              // max embedded payload fraction (fixed)
	page[22] = 32                              // min embedded payload fraction (fixed)
	page[23] = 32                              // leaf payload fraction (fixed)
	binary.BigEndian.PutUint32(page[24:28], 1) // file change counter
	binary.BigEndian.PutUint32(page[28:32], 1) // database size in pages
	// bytes 32..43: freelist trunk + count = 0; schema cookie (40..43) = 0
	binary.BigEndian.PutUint32(page[44:48], 4) // schema format number (4 = current)
	// bytes 48..55: default page cache = 0; largest-root-page (autovacuum) = 0
	binary.BigEndian.PutUint32(page[56:60], 1) // text encoding = 1 (UTF-8)
	// bytes 60..91: user version, incremental-vacuum, application id, reserved = 0
	binary.BigEndian.PutUint32(page[92:96], 1)        // version-valid-for = change counter ⇒ trust header size
	binary.BigEndian.PutUint32(page[96:100], 3046000) // SQLITE_VERSION_NUMBER (informational)

	// ── page-1 b-tree page header (begins at byte 100, after the db header) ──
	usable := ps - Reserve
	page[100] = 0x0D                                          // leaf table b-tree page
	binary.BigEndian.PutUint16(page[101:103], 0)              // first freeblock (none)
	binary.BigEndian.PutUint16(page[103:105], 0)              // number of cells
	binary.BigEndian.PutUint16(page[105:107], uint16(usable)) // cell content area start = usable size
	page[107] = 0                                             // fragmented free bytes
	// no cell pointers, no cells; the rest of the usable region is free space and
	// the final Reserve bytes are the (unused, plaintext) reserve.

	return page, nil
}
