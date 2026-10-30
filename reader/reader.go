// Package reader opens SQLCipher databases read-only, in pure Go, with no cgo.
//
// It decrypts pages in memory as SQLite asks for them and never writes: the
// database file is not modified, not even by a failed write. Use it to verify a
// backup or replica, to run reports or forensics over an encrypted store, and to
// read a ledger during migration — anywhere a C toolchain is unwelcome.
//
// # Why read-only, and why that is not a limitation of ambition
//
// SQLCipher's codec is a hook inside SQLite's pager, above the VFS, and the pager
// encrypts WAL frames and rollback-journal records too — whose checksums SQLite
// computes over the resulting ciphertext. A VFS-level codec sits below the pager,
// so it cannot reproduce those sidecars: SQLite would checksum plaintext while the
// VFS wrote ciphertext, and cross-engine recovery would silently drop committed
// transactions. Reading has no WAL frames and no journal records to get wrong, so
// the blocker that rules out a read-write VFS does not apply here. This package is
// exactly the part that is safe, and it refuses the part that is not.
//
// # What it refuses
//
// Open fails, rather than returning a plausible answer, when:
//
//   - the key is wrong (page 1 does not authenticate),
//   - a non-empty -wal or -journal sits beside the database.
//
// The second is the important one. Either file may hold committed data that is not
// yet in the main database, or uncommitted data that must be rolled back out of it.
// Whether a WAL is fully checkpointed cannot be settled from the file alone, so
// reading the main database while ignoring them could hand back stale or
// uncommitted numbers — silently, and off the money path is not where that is
// discovered. Checkpoint and close the database cleanly, then read it.
package reader

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/Yeadear/sqlcipher"
	_ "modernc.org/sqlite" // registers the "sqlite" driver this opens through
	"modernc.org/sqlite/vfs"
)

// ErrBusy reports that a -wal or -journal sits beside the database, so the main
// file alone is not the whole truth. It is not a lock: it means the database was
// not closed cleanly and reading it could return stale or uncommitted data.
var ErrBusy = errors.New("sqlcipher/reader: database has a -wal or -journal beside it and may not be up to date; checkpoint and close it cleanly first")

// name is what the database is called inside the private file system handed to
// SQLite. The real path never reaches SQLite, so it cannot be reopened, guessed
// at, or written through by path.
const name = "db"

// DB is a read-only handle to an encrypted database. Close it to release both the
// pool and the file system registered for it.
type DB struct {
	*sql.DB
	fsys *vfs.FS
}

// Close closes the pool and unregisters the file system.
func (db *DB) Close() error {
	err := db.DB.Close()
	if ferr := db.fsys.Close(); err == nil {
		err = ferr
	}
	return err
}

// Open opens the SQLCipher database at path read-only. A wrong key is reported
// here, at open, rather than as corruption later.
func Open(path string, k sqlcipher.Key, p sqlcipher.Params) (*DB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}

	s, err := newStore(f, st.Size(), k, p)
	if err != nil {
		f.Close()
		return nil, err
	}
	if err := checkQuiet(path); err != nil {
		f.Close()
		return nil, err
	}

	id, fsys, err := vfs.New(s)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("sqlcipher/reader: register file system: %w", err)
	}
	// immutable=1 is load-bearing, not decoration, and mode=ro alone is NOT
	// enough. SQLite normally decides read-only from the flags the VFS reports
	// back out of xOpen (pager.c: readOnly = (fout&SQLITE_OPEN_READONLY)!=0),
	// and modernc's read-only VFS reports os.O_RDONLY there — which is 0, where
	// SQLITE_OPEN_READONLY is 1. The bit is dropped, so mode=ro silently yields a
	// read-WRITE pager and the only thing left refusing writes is that VFS's
	// blanket refusal to open a journal. PRAGMA journal_mode=MEMORY removes even
	// that, and the next write reaches the VFS's null xWrite and segfaults the
	// process. immutable=1 takes a different route (pager.c: vfsFlags |=
	// SQLITE_OPEN_READONLY, then act_like_temp_file derives readOnly from
	// vfsFlags rather than from the VFS), so the pager really is read-only, the
	// btree gets BTS_READ_ONLY, and writes are refused before any journal or page
	// write. It cannot be turned off from SQL, which is why it is preferred over
	// PRAGMA query_only. mode=ro stays because it states the intent and becomes
	// the real gate if modernc ever reports the flag correctly.
	//
	// immutable also tells SQLite the file cannot change underneath it, which is
	// true of what this package is for — a snapshot, a backup, a replica, a
	// cleanly closed store — and is why Open refuses a database with a live
	// sidecar. Do not point it at a file another process is writing.
	db, err := sql.Open("sqlite", "file:"+name+"?vfs="+id+"&mode=ro&immutable=1")
	if err != nil {
		fsys.Close()
		f.Close()
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		fsys.Close()
		f.Close()
		return nil, fmt.Errorf("sqlcipher/reader: open %s: %w", path, err)
	}
	if err := proveReadOnly(db); err != nil {
		db.Close()
		fsys.Close()
		f.Close()
		return nil, err
	}
	return &DB{DB: db, fsys: fsys}, nil
}

// proveReadOnly refuses to hand back a handle whose read-only guard is not
// actually in force. The guard depends on how SQLite and modernc's VFS interact
// (see the DSN comment above), and getting it wrong does not fail loudly — it
// segfaults on the first write. So it is checked rather than assumed, once, at
// open: a write that is refused proves the pager is read-only; a write that
// succeeds means the database is writable and must not be handed out as a reader.
func proveReadOnly(db *sql.DB) error {
	_, err := db.Exec("PRAGMA user_version = 1")
	if err == nil {
		return errors.New("sqlcipher/reader: refusing to open: the read-only guard is not in force, this handle could modify the database")
	}
	return nil
}

// checkQuiet refuses a database whose sidecars may hold data the main file does
// not. A zero-length -wal is what a cleanly closed database in persistent-WAL
// mode leaves behind and carries no frames, so it is allowed.
func checkQuiet(path string) error {
	for _, suffix := range []string{"-wal", "-journal"} {
		st, err := os.Stat(path + suffix)
		if err != nil {
			continue // absent is what we want
		}
		if st.Size() > 0 {
			return fmt.Errorf("%w: %s is %d bytes", ErrBusy, filepath.Base(path+suffix), st.Size())
		}
	}
	return nil
}

// store is the decrypting file system handed to SQLite: exactly one file, no
// directory, no writes.
type store struct {
	src   io.ReaderAt
	size  int64
	codec *sqlcipher.Codec
}

func newStore(src io.ReaderAt, size int64, k sqlcipher.Key, p sqlcipher.Params) (*store, error) {
	head := make([]byte, sqlcipher.SaltSize)
	if _, err := src.ReadAt(head, 0); err != nil {
		return nil, fmt.Errorf("sqlcipher/reader: read salt: %w", err)
	}
	salt, err := sqlcipher.FileSalt(head)
	if err != nil {
		return nil, err
	}
	c, err := sqlcipher.NewCodec(k, salt, p)
	if err != nil {
		return nil, err
	}
	if size == 0 || size%int64(c.PageSize()) != 0 {
		return nil, fmt.Errorf("sqlcipher/reader: %d bytes is not a whole number of %d-byte pages", size, c.PageSize())
	}

	s := &store{src: src, size: size, codec: c}
	// Decrypting page 1 authenticates it, so a wrong key is caught here rather
	// than surfacing as corruption once SQLite starts reading.
	page1, err := s.page(1)
	if err != nil {
		return nil, err
	}
	if got := page1[20]; got != sqlcipher.Reserve {
		return nil, fmt.Errorf("sqlcipher/reader: page reserve is %d, want %d", got, sqlcipher.Reserve)
	}
	return s, nil
}

// page decrypts one page by number.
func (s *store) page(pgno uint32) ([]byte, error) {
	buf := make([]byte, s.codec.PageSize())
	if _, err := s.src.ReadAt(buf, int64(pgno-1)*int64(s.codec.PageSize())); err != nil {
		return nil, fmt.Errorf("sqlcipher/reader: read page %d: %w", pgno, err)
	}
	return s.codec.Decrypt(pgno, buf)
}

// Open implements fs.FS. It serves the one database and nothing else, so SQLite's
// probes for a journal or WAL inside this file system find nothing.
func (s *store) Open(n string) (fs.File, error) {
	if n != name {
		return nil, &fs.PathError{Op: "open", Path: n, Err: fs.ErrNotExist}
	}
	return &file{store: s}, nil
}

// file is a read cursor over the decrypted database. modernc's VFS seeks and then
// reads, so it needs io.Seeker as well as fs.File.
type file struct {
	*store
	off    int64
	cached uint32 // page number held in page, 0 when empty
	page   []byte
}

func (f *file) Stat() (fs.FileInfo, error) { return info{size: f.size}, nil }
func (f *file) Close() error               { return nil }

func (f *file) Seek(off int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		off += f.off
	case io.SeekEnd:
		off += f.size
	default:
		return 0, fmt.Errorf("sqlcipher/reader: bad whence %d", whence)
	}
	if off < 0 {
		return 0, fmt.Errorf("sqlcipher/reader: negative offset %d", off)
	}
	f.off = off
	return off, nil
}

func (f *file) Read(b []byte) (int, error) {
	if f.off >= f.size {
		return 0, io.EOF
	}
	ps := int64(f.codec.PageSize())
	n := 0
	for n < len(b) && f.off < f.size {
		pgno := uint32(f.off/ps) + 1
		if f.cached != pgno {
			page, err := f.store.page(pgno)
			if err != nil {
				return n, err
			}
			f.page, f.cached = page, pgno
		}
		c := copy(b[n:], f.page[f.off%ps:])
		n += c
		f.off += int64(c)
	}
	return n, nil
}

// info is the minimum fs.FileInfo modernc's VFS reads: it asks only for Size.
type info struct{ size int64 }

func (i info) Name() string       { return name }
func (i info) Size() int64        { return i.size }
func (i info) Mode() fs.FileMode  { return 0o400 }
func (i info) ModTime() time.Time { return time.Time{} }
func (i info) IsDir() bool        { return false }
func (i info) Sys() any           { return nil }
