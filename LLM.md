# hanzoai/sqlcipher — engineering notes

The SQLCipher 4 page format in pure Go. Ported from the C source (v4.5.6), not
written from a spec: the docs are incomplete and the source is what defines the
format. Zero dependencies — every primitive is stdlib.

## Why this is its own module

The format is one concern; a driver is another. Trapping the codec inside
`hanzoai/sqlite` would brand a reusable value with a place. Anything that must
read or write SQLCipher files — the driver, `replicate`/backup, a migration, a
forensic tool — depends on this and nothing else.

## Verified constants (do not "clean up")

Taken from `src/crypto.h` + `src/crypto_impl.c` at v4.5.6 and confirmed against a
live `libsqlcipher` 4.5.6 via `PRAGMA cipher_*`:

| Constant | Value | Source |
|---|---|---|
| `PBKDF2_ITER` | 256000 | `crypto.h:102` |
| `FAST_PBKDF2_ITER` | 2 | `crypto.h:126` |
| `HMAC_SALT_MASK` | `0x3a` | `crypto.h:135` |
| `FILE_HEADER_SZ` | 16 | `crypto.h:81` |
| `DEFAULT_CIPHER_FLAGS` | `HMAC \| LE_PGNO` | `crypto.h:118` |
| key / IV / block / HMAC | 32 / 16 / 16 / 64 | `crypto_openssl.c` |
| reserve | 80 | `(iv+hmac)` rounded up to block size |
| cipher | `EVP_aes_256_cbc()`, `set_padding(0)` | `crypto_openssl.c:91,401` |

Getting one of these wrong means **silently unreadable data**, so they are pinned
by golden vectors *and* by fixtures the C library wrote.

**4.5.6 vs 4.6.1 (what production ships):** identical format. 4.6.1 merged
`crypto.h`/`crypto.c`/`crypto_impl.c` into one `sqlcipher.c`; diffing
`sqlcipher_page_cipher`, `sqlcipher_page_hmac`, `sqlcipher_cipher_ctx_key_derive`
and `sqlcipher_codec_ctx_reserve_setup` across the two tags shows only log-call
signatures, a `static` qualifier, and `sqlcipher_codec_ctx_get_use_hmac(ctx)`
replaced by the equivalent `SQLCIPHER_FLAG_GET(ctx->flags, CIPHER_FLAG_HMAC)`.

## Two subtleties that will bite a refactor

1. **The reserve travels in the database header** (SQLite byte 20 = 80). This is
   why reading an existing SQLCipher database needs no configuration: SQLite's
   `lockBtree` sets `usableSize = pageSize - page1[20]` from the file itself.
   Confirmed empirically — `modernc.org/sqlite` inserts correctly into a
   decrypted reserve=80 database and the C library reads the result.
2. **A decrypted page's reserve holds the IV**, which is fresh on every write. So
   `decrypt → encrypt → decrypt` is the identity on the *usable* bytes, not on the
   trailer. Do not "fix" a round-trip test by comparing whole pages.

## VFS vs codec — settled, with evidence

The question was whether a VFS-level layer over `modernc.org/sqlite` could
implement this format and give us an encrypting pure-Go engine. **It cannot.**
Three independent blockers, in order of severity:

1. **The codec is a *pager* hook, not a VFS hook, and the WAL/journal checksums
   cover ciphertext.** `wal.c:3852` calls `sqlcipherPagerCodec(pPage)` and *then*
   `walEncodeFrame` checksums that ciphertext; `pager.c:4657/6102` do the same for
   the rollback journal and subjournal via `CODEC2`. A VFS shim sits *below* the
   pager, so SQLite would checksum the plaintext while the shim wrote ciphertext.
   Verified numerically against a real hot C-written WAL: recomputing
   `walChecksumBytes` over the **on-disk (encrypted)** bytes reproduces the stored
   frame checksums exactly, on every frame. Consequence: a Go process could not
   recover a C-written hot WAL, and vice versa — recovery would stop at the first
   frame and **silently drop committed transactions**. The main database file
   alone *is* byte-compatible; the sidecars are not.
2. **`modernc.org/sqlite/vfs` is read-only.** It is `fs.FS`-backed; `vfsio` fills
   only `xClose/xRead/xFileSize/xLock/xUnlock/xCheckReservedLock/xFileControl/
   xSectorSize/xDeviceCharacteristics` — the `xWrite`/`xTruncate`/`xSync` slots
   (offsets +24/+32/+40) are left null. `vfsOpen` refuses `SQLITE_OPEN_MAIN_JOURNAL`
   and `xAccess` reports not-writable. There is no Go-native read-write VFS API; a
   shim would mean hand-building `sqlite3_vfs`/`sqlite3_io_methods` through
   hardcoded struct offsets and `unsafe`.
3. **The reserve cannot be set on a *new* database.** `fcntl.go` exports only
   `FileControlPersistWAL`; the generic `fileControl` is unexported, so
   `SQLITE_FCNTL_RESERVE_BYTES` is unreachable. Existing databases are fine
   (blocker 1 aside) because the reserve is in the header.

**The path that does work** — should we want a real pure-Go SQLCipher engine — is
to transpile SQLCipher's own amalgamation with `ccgo` (exactly how
`modernc.org/sqlite` is built from `sqlite3.c`) and register a Go crypto provider
via `sqlcipher_register_provider()`, which is public API (`sqlcipher.h:87`). That
is byte-compatible *by construction* — it is SQLCipher's own pager, wal and codec —
and the Go provider is where a post-quantum AEAD would plug in later. It is a
build-toolchain project, not a codec project.

## What this module does not do

It does not encrypt a live database. Use it for offline read/write, tooling,
migration and verification, and as the format seam for any future engine work.
