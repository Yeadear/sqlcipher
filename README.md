# Hanzo SQLCipher — NTQQ fork

> **This is a fork of [`hanzoai/sqlcipher`](https://github.com/hanzoai/sqlcipher).**
> Upstream is © the original authors; see [NOTICE](NOTICE).
>
> The only change here is that the **page HMAC algorithm is configurable**.
> Upstream hardcodes the SQLCipher 4 defaults (HMAC-SHA512, 256000 PBKDF2 rounds,
> reserve 80). QQ NT (`nt_msg.db`) uses a *mixed* set of parameters —
> `kdf_iter=4000`, `cipher_kdf_algorithm=PBKDF2_HMAC_SHA512` but
> `cipher_hmac_algorithm=HMAC_SHA1` — which upstream cannot open.
>
> So this fork adds a `HMACAlgo` to `Params` and derives the per-page reserve from
> it:

```go
err := sqlcipher.DecryptFile(out, in, sqlcipher.RawKey(key), sqlcipher.Params{
    PageSize: 4096,
    Iter:     4000,
    HMAC:     sqlcipher.HMACSHA1, // reserve becomes IV(16) + HMAC slot(32) = 48
})
```

> Everything else (KDF, AES-256-CBC, page layout, `ErrKey` on a wrong key) is
> untouched, and the SQLCipher 4 defaults remain the default, so this is a
> drop-in replacement for upstream.

---

# Hanzo SQLCipher

The **SQLCipher 4 on-disk page format**, in pure Go, with **zero dependencies**.

A port of the SQLCipher codec ([sqlcipher/sqlcipher](https://github.com/sqlcipher/sqlcipher)
v4.5.6, BSD-3, © ZETETIC LLC — see [NOTICE](NOTICE)). It is the format and only the
format: it knows nothing about `database/sql`, drivers or engines, so a driver, a
backup or replication path, a migration or a forensic tool can all read and write
SQLCipher files without dragging in a SQL engine.

**It is byte-compatible with the C library in both directions** — it reads
databases `libsqlcipher` wrote, and `libsqlcipher` reads databases it writes. No
migration, no new format.

```go
// Decrypt a SQLCipher database into a plaintext SQLite database.
in, _ := os.Open("encrypted.db")
out, _ := os.Create("plain.db")
err := sqlcipher.DecryptFile(out, in, sqlcipher.RawKey(key), sqlcipher.Params{})

// Or work a page at a time.
salt, _ := sqlcipher.FileSalt(page1)
c, _ := sqlcipher.NewCodec(sqlcipher.RawKey(key), salt, sqlcipher.Params{})
plain, err := c.Decrypt(pgno, page) // ErrKey on a wrong key — never garbage
```

## The format

```
page 1 on disk:  [ salt (16) | ciphertext | IV (16) | HMAC-SHA512 (64) ]
page N on disk:  [            ciphertext | IV (16) | HMAC-SHA512 (64) ]
```

Pages are independent — no cross-page state, no chaining. The salt is the first
16 bytes of page 1 and is the only plaintext in the file; page 1 therefore
encrypts only the bytes after it, and decrypting restores SQLite's
`SQLite format 3\0` magic over it.

The IV and tag live in SQLite's **per-page reserve**, which SQLite records in
**byte 20 of the database header** — so an encrypted database carries its own
reserve size and needs no out-of-band configuration to be read.

| | |
|---|---|
| Cipher | AES-256-CBC, no padding |
| Authentication | HMAC-SHA512 over `ciphertext ‖ IV ‖ pgno_le32` |
| Passphrase KDF | PBKDF2-HMAC-SHA512, 256000 iterations |
| Page-auth key | PBKDF2-HMAC-SHA512 of the page key over `salt ⊕ 0x3a`, 2 iterations |
| Page size | 4096 (default) |
| Reserve | 80 = IV(16) + HMAC(64) |

Every constant was taken from the C source and confirmed against a live
`libsqlcipher`. The format is **unchanged between 4.5.6 and 4.6.1** (4.6.1 merged
`crypto.h`/`crypto.c`/`crypto_impl.c` into `sqlcipher.c` — a refactor, not a
format change).

## Failing closed

`Decrypt` authenticates **before** it decrypts. A wrong key, a wrong salt, a
flipped bit in the ciphertext, the IV or the tag, or a valid page replayed at
another page number all return `ErrKey` with no data. It never returns garbage
plaintext, and it never silently persists plaintext.

## Proof

`go test ./...` — 28 tests, no C toolchain needed. Golden vectors pin the KDF, the
page-auth key and the exact bytes of a page under a fixed IV, so a refactor cannot
silently change the format. Vectors alone would only pin the port to itself, so
both keying paths are cross-verified against databases **the C library actually
wrote**, committed as fixtures:

- `testdata/c-4.5.6.db` — raw key, 7 pages, overflow + index + random/zero blobs
- `testdata/c-4.5.6-passphrase.db` — passphrase, proving PBKDF2 at 256000 iterations agrees

`cd parity && go test ./...` — the full cross-engine gate, needing `libsqlcipher`
and a C compiler: the C library writes → pure Go reads → `modernc.org/sqlite`
writes into the decrypted database → pure Go encrypts → **the C library reads back
what Go wrote**.

## Scope

This is the format, not an engine. It gives you offline read/write of SQLCipher
files. It does **not** turn a pure-Go SQLite into an encrypting one: SQLCipher's
codec is a hook inside SQLite's *pager*, above the VFS, and it encrypts WAL frames
and rollback-journal records too — whose checksums SQLite computes over the
**ciphertext**. A VFS-level codec sits below the pager and cannot reproduce that.
See `LLM.md` for the evidence.

## License

BSD-3-Clause. Ported from SQLCipher; ZETETIC LLC's copyright and the full BSD-3
notice are retained in [LICENSE](LICENSE). SQLCipher is a trademark of ZETETIC LLC;
this project is not affiliated with or endorsed by them.
