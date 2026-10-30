// Package parity proves byte-compatibility with the real C SQLCipher library in
// both directions, using two independent engines as oracles:
//
//	the C library (libsqlcipher, via the cref tool) writes and reads
//	pure Go (this port + modernc.org/sqlite) writes and reads
//
// It is a separate module so the format package itself keeps zero dependencies.
// It needs libsqlcipher and a C compiler, so it is skipped where they are absent;
// the format package's fixture tests cover the C-written direction everywhere.
package parity

import (
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yeadear/sqlcipher"
	_ "modernc.org/sqlite"
)

const keyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

var key = func() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}()

// cref builds a small C program against libsqlcipher: the reference writer and
// reader. Skips the whole suite when the toolchain or library is absent.
func cref(t *testing.T) func(args ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("no C compiler: cannot exercise the C SQLCipher library")
	}
	if _, err := os.Stat("/usr/include/sqlcipher/sqlite3.h"); err != nil {
		t.Skip("libsqlcipher headers absent: cannot exercise the C SQLCipher library")
	}
	bin := filepath.Join(t.TempDir(), "cref")
	out, err := exec.Command("gcc", "-O1", "-o", bin, "testdata/cref.c", "-lsqlcipher").CombinedOutput()
	if err != nil {
		t.Skipf("cannot build against libsqlcipher: %v\n%s", err, out)
	}
	return func(args ...string) (string, error) {
		o, err := exec.Command(bin, args...).CombinedOutput()
		return string(o), err
	}
}

func convert(t *testing.T, dst, src string, enc bool, salt []byte) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	if enc {
		err = sqlcipher.EncryptFile(out, in, sqlcipher.RawKey(key), salt, sqlcipher.Params{})
	} else {
		err = sqlcipher.DecryptFile(out, in, sqlcipher.RawKey(key), sqlcipher.Params{})
	}
	if err != nil {
		t.Fatal(err)
	}
}

func rows(t *testing.T, path string) []string {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(DELETE)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rs, err := db.Query("SELECT id, v FROM t ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	var out []string
	for rs.Next() {
		var id int
		var v string
		if err := rs.Scan(&id, &v); err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	if err := rs.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestParity is the gate. If it fails, the port has drifted from the format and
// no production database can be read.
func TestParity(t *testing.T) {
	run := cref(t)
	dir := t.TempDir()
	cdb := filepath.Join(dir, "c.db")
	plain := filepath.Join(dir, "plain.db")
	godb := filepath.Join(dir, "go.db")

	// --- C SQLCipher writes -> pure Go reads ---
	if out, err := run("create", cdb, keyHex); err != nil {
		t.Fatalf("C library failed to create a database: %v\n%s", err, out)
	}
	enc, err := os.ReadFile(cdb)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(string(enc), "SQLite format 3") {
		t.Fatal("the C library wrote a plaintext header: it is not linked against SQLCipher")
	}

	convert(t, plain, cdb, false, nil)

	pt, err := os.ReadFile(plain)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(pt), "SQLite format 3\x00") {
		t.Fatalf("pure Go did not decrypt page 1 to a SQLite header: %q", pt[:16])
	}
	// The reserve travels in the database header, which is why an existing
	// SQLCipher database needs no out-of-band configuration to be read.
	if pt[20] != sqlcipher.Reserve {
		t.Fatalf("header byte 20 (reserve) = %d, want %d", pt[20], sqlcipher.Reserve)
	}
	if got := rows(t, plain); len(got) != 1 || got[0] != "hello-from-c" {
		t.Fatalf("pure Go read %v from a C-written database, want [hello-from-c]", got)
	}

	// --- pure Go writes -> C SQLCipher reads ---
	// modernc writes into the reserve=80 database, honouring the reserve it read
	// from the header, then this port encrypts what it wrote.
	db, err := sql.Open("sqlite", "file:"+plain+"?_pragma=journal_mode(DELETE)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO t(v) VALUES('hello-from-go')"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	salt, err := sqlcipher.FileSalt(enc)
	if err != nil {
		t.Fatal(err)
	}
	convert(t, godb, plain, true, salt)

	if b, err := os.ReadFile(godb); err != nil {
		t.Fatal(err)
	} else if strings.HasPrefix(string(b), "SQLite format 3") {
		t.Fatal("pure Go wrote a plaintext header")
	}

	out, err := run("read", godb, keyHex)
	if err != nil {
		t.Fatalf("the C SQLCipher library could not read a pure-Go-written database: %v\n%s", err, out)
	}
	for _, want := range []string{"hello-from-c", "hello-from-go"} {
		if !strings.Contains(out, want) {
			t.Errorf("the C library did not read back %q\n%s", want, out)
		}
	}
}

// TestParityNewDatabaseFromSeed is the byte-compatibility gate for a database
// CREATED from nothing in pure Go: EmptyPlaintext mints the reserve-80 seed,
// modernc writes a table into it (honouring the reserve from the header), this
// port encrypts it, and the C SQLCipher library reads back what Go wrote. This is
// the new-database path a pure-Go encrypting driver takes when no file exists yet.
func TestParityNewDatabaseFromSeed(t *testing.T) {
	run := cref(t)
	dir := t.TempDir()
	plain := filepath.Join(dir, "seed.db")
	godb := filepath.Join(dir, "seeded-go.db")

	// 1) Mint the pure-Go seed and write a schema + row through modernc.
	seed, err := sqlcipher.EmptyPlaintext(sqlcipher.Params{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plain, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+plain+"?_pragma=journal_mode(DELETE)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)"); err != nil {
		db.Close()
		t.Fatalf("modernc could not create a table in the seed: %v", err)
	}
	if _, err := db.Exec("INSERT INTO t(v) VALUES('seed-then-encrypt')"); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()

	// The reserve must survive modernc's writes, or EncryptFile has no room.
	pt, err := os.ReadFile(plain)
	if err != nil {
		t.Fatal(err)
	}
	if pt[20] != sqlcipher.Reserve {
		t.Fatalf("modernc dropped the reserve: header byte 20 = %d, want %d", pt[20], sqlcipher.Reserve)
	}

	// 2) Encrypt with a fresh salt (nil) — a brand-new database.
	convert(t, godb, plain, true, nil)
	if b, err := os.ReadFile(godb); err != nil {
		t.Fatal(err)
	} else if strings.HasPrefix(string(b), "SQLite format 3") {
		t.Fatal("pure Go wrote a plaintext header for a new database")
	}

	// 3) The C library reads the pure-Go-seeded, pure-Go-encrypted database.
	out, err := run("read", godb, keyHex)
	if err != nil {
		t.Fatalf("the C SQLCipher library could not read a pure-Go seed-then-encrypt database: %v\n%s", err, out)
	}
	if !strings.Contains(out, "seed-then-encrypt") {
		t.Errorf("the C library did not read back the seeded row\n%s", out)
	}
}

// TestWrongKeyFailsClosed: the C library refuses a database under the wrong key,
// and so must this port.
func TestWrongKeyFailsClosed(t *testing.T) {
	run := cref(t)
	dir := t.TempDir()
	cdb := filepath.Join(dir, "c.db")
	if out, err := run("create", cdb, keyHex); err != nil {
		t.Fatalf("create: %v\n%s", err, out)
	}
	if _, err := run("read", cdb, strings.Repeat("ff", 32)); err == nil {
		t.Fatal("the C library accepted a wrong key")
	}

	in, err := os.Open(cdb)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	bad := make([]byte, 32)
	err = sqlcipher.DecryptFile(os.NewFile(0, os.DevNull), in, sqlcipher.RawKey(bad), sqlcipher.Params{})
	if err == nil {
		t.Fatal("FAIL OPEN: this port accepted a wrong key")
	}
	t.Logf("wrong key -> %v", err)
}
