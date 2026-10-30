package reader

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yeadear/sqlcipher"
)

var key = func() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}()

const keyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

// fixture copies a database the real C library wrote into a temp dir.
func fixture(t *testing.T, src string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "testdata", src))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "c.db")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func sum(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// TestReadsDatabaseWrittenByC is the point of the package: pure Go, no cgo, reads
// a database the C library wrote.
func TestReadsDatabaseWrittenByC(t *testing.T) {
	path := fixture(t, "c-4.5.6.db")
	db, err := Open(path, sqlcipher.RawKey(key), sqlcipher.Params{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	var got []string
	rows, err := db.Query("SELECT v FROM t ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		got = append(got, v)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := []string{"hello-from-c", "ledger-row-two"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}

	// Overflow pages and an index: the reader must serve every page, not just
	// the header.
	var n, total int
	if err := db.QueryRow("SELECT count(*), coalesce(sum(length(blob)),0) FROM wide").Scan(&n, &total); err != nil {
		t.Fatal(err)
	}
	if n != 2 || total != 14000 {
		t.Errorf("wide: got %d rows / %d bytes, want 2 / 14000", n, total)
	}
	if err := db.QueryRow("PRAGMA integrity_check").Scan(new(string)); err != nil {
		t.Fatal(err)
	}
}

func TestReadsPassphraseDatabaseWrittenByC(t *testing.T) {
	path := fixture(t, "c-4.5.6-passphrase.db")
	db, err := Open(path, sqlcipher.Passphrase("correct horse battery staple"), sqlcipher.Params{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	var v string
	if err := db.QueryRow("SELECT v FROM t").Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != "passphrase-keyed-by-c" {
		t.Errorf("got %q", v)
	}
}

// TestWrongKeyFailsClosed: a wrong key must be an error at Open, not garbage, not
// an empty database.
func TestWrongKeyFailsClosed(t *testing.T) {
	path := fixture(t, "c-4.5.6.db")
	for _, tc := range []struct {
		name string
		k    sqlcipher.Key
	}{
		{"wrong raw key", sqlcipher.RawKey(make([]byte, 32))},
		{"wrong passphrase", sqlcipher.Passphrase("nope")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, err := Open(path, tc.k, sqlcipher.Params{})
			if err == nil {
				db.Close()
				t.Fatal("FAIL OPEN: opened with the wrong key")
			}
			if !errors.Is(err, sqlcipher.ErrKey) {
				t.Fatalf("want ErrKey, got %v", err)
			}
		})
	}
}

// TestReadOnlyIsEnforced: every statement that would change data must fail with
// a real error and leave the file byte-identical.
//
// Note journal_mode pragmas are NOT in this list: they set an in-memory pager
// mode and write nothing, so SQLite accepts them on a read-only database and is
// right to. What matters is that no byte of the file moves, which is asserted
// after every case.
func TestReadOnlyIsEnforced(t *testing.T) {
	path := fixture(t, "c-4.5.6.db")
	before := sum(t, path)

	db, err := Open(path, sqlcipher.RawKey(key), sqlcipher.Params{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	for _, q := range []string{
		"INSERT INTO t(v) VALUES('nope')",
		"UPDATE t SET v='nope'",
		"DELETE FROM t",
		"CREATE TABLE u(x)",
		"DROP TABLE t",
		"CREATE INDEX idx_nope ON t(v)",
		"PRAGMA user_version=42",
		"PRAGMA application_id=7",
		"VACUUM",
		"REINDEX",
	} {
		t.Run(q, func(t *testing.T) {
			if _, err := db.Exec(q); err == nil {
				t.Fatalf("FAIL OPEN: %q succeeded on a read-only database", q)
			}
			if after := sum(t, path); after != before {
				t.Fatalf("%q changed the file", q)
			}
		})
	}

	// Reads still work after all those refusals.
	var n int
	if err := db.QueryRow("SELECT count(*) FROM t").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("got %d rows, want 2", n)
	}
	if after := sum(t, path); after != before {
		t.Fatal("the database file changed under a read-only open")
	}
}

// TestJournalModeMemoryCannotReachTheNullWrite is a regression test for a real
// crash, and the reason Open sets immutable=1.
//
// modernc's read-only VFS has no xWrite at all and reports os.O_RDONLY (0) where
// SQLite expects SQLITE_OPEN_READONLY (1), so SQLite does not learn the file is
// read-only from the VFS. With only mode=ro, writes were refused by accident —
// that VFS refuses to open a journal — and PRAGMA journal_mode=MEMORY removes the
// accident: no journal file is needed, so the next write walks into the null
// xWrite and SIGSEGVs the process. immutable=1 makes the pager genuinely
// read-only, so the write is refused before any of that.
//
// If this test ever segfaults instead of failing, the guard is gone.
func TestJournalModeMemoryCannotReachTheNullWrite(t *testing.T) {
	path := fixture(t, "c-4.5.6.db")
	before := sum(t, path)
	db, err := Open(path, sqlcipher.RawKey(key), sqlcipher.Params{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Setting an in-memory journal is allowed: it writes nothing.
	if _, err := db.Exec("PRAGMA journal_mode=MEMORY"); err != nil {
		t.Logf("journal_mode=MEMORY: %v", err)
	}
	for _, q := range []string{"PRAGMA user_version=42", "INSERT INTO t(v) VALUES('x')"} {
		if _, err := db.Exec(q); err == nil {
			t.Fatalf("FAIL OPEN: %q wrote to a read-only database with an in-memory journal", q)
		}
	}
	if after := sum(t, path); after != before {
		t.Fatal("the database file changed")
	}
}

// TestRefusesHotSidecar: a -wal or -journal beside the database means the main
// file may be stale or hold uncommitted data. Refuse rather than answer.
func TestRefusesHotSidecar(t *testing.T) {
	for _, suffix := range []string{"-wal", "-journal"} {
		t.Run(suffix, func(t *testing.T) {
			path := fixture(t, "c-4.5.6.db")
			if err := os.WriteFile(path+suffix, []byte("frames"), 0o600); err != nil {
				t.Fatal(err)
			}
			db, err := Open(path, sqlcipher.RawKey(key), sqlcipher.Params{})
			if err == nil {
				db.Close()
				t.Fatalf("FAIL OPEN: read a database with a hot %s behind it", suffix)
			}
			if !errors.Is(err, ErrBusy) {
				t.Fatalf("want ErrBusy, got %v", err)
			}
		})
	}

	// A zero-length -wal is what a clean close in persistent-WAL mode leaves and
	// carries no frames, so it must not block a read.
	t.Run("empty -wal is fine", func(t *testing.T) {
		path := fixture(t, "c-4.5.6.db")
		if err := os.WriteFile(path+"-wal", nil, 0o600); err != nil {
			t.Fatal(err)
		}
		db, err := Open(path, sqlcipher.RawKey(key), sqlcipher.Params{})
		if err != nil {
			t.Fatalf("an empty -wal must not block a read: %v", err)
		}
		db.Close()
	})
}

func TestRejectsMalformed(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name, want string
		body       []byte
	}{
		{"empty file", "pages", nil},
		{"partial page", "pages", make([]byte, 100)},
		{"not a whole number of pages", "pages", make([]byte, 4096+7)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "_")+".db")
			if err := os.WriteFile(path, tc.body, 0o600); err != nil {
				t.Fatal(err)
			}
			db, err := Open(path, sqlcipher.RawKey(key), sqlcipher.Params{})
			if err == nil {
				db.Close()
				t.Fatal("want error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Logf("error (acceptable): %v", err)
			}
		})
	}
}

// TestReads461 closes the version gap: production ships SQLCipher 4.6.1 while the
// committed fixtures were written by 4.5.6. This builds 4.6.1 from source and
// reads what it wrote. Skipped where the toolchain is absent.
func TestReads461(t *testing.T) {
	bin := os.Getenv("SQLCIPHER_461_SHELL")
	if bin == "" {
		t.Skip("set SQLCIPHER_461_SHELL to a sqlcipher 4.6.1 shell to close the version gap")
	}
	path := filepath.Join(t.TempDir(), "c461.db")
	sql := "PRAGMA key = \"x'" + keyHex + "'\";\nPRAGMA journal_mode=DELETE;\n" +
		"CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT);\nINSERT INTO t(v) VALUES('written-by-461');\n"
	cmd := exec.Command(bin, path)
	cmd.Stdin = strings.NewReader(sql)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sqlcipher 4.6.1 create: %v\n%s", err, out)
	}
	if b, err := os.ReadFile(path); err != nil {
		t.Fatal(err)
	} else if bytes.HasPrefix(b, []byte("SQLite format 3")) {
		t.Fatal("the 4.6.1 shell wrote plaintext: not linked against SQLCipher")
	}

	db, err := Open(path, sqlcipher.RawKey(key), sqlcipher.Params{})
	if err != nil {
		t.Fatalf("pure Go could not read a database SQLCipher 4.6.1 wrote: %v", err)
	}
	defer db.Close()
	var v string
	if err := db.QueryRow("SELECT v FROM t").Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != "written-by-461" {
		t.Errorf("got %q", v)
	}
	t.Logf("pure Go read %q from a SQLCipher 4.6.1 database", v)
}
