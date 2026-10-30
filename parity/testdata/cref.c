/* C SQLCipher reference tool: ground truth for the port. */
#include <sqlcipher/sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void show(sqlite3 *db, const char *p) {
  sqlite3_stmt *s; char q[128];
  snprintf(q, sizeof q, "PRAGMA %s;", p);
  if (sqlite3_prepare_v2(db, q, -1, &s, 0) != SQLITE_OK) { printf("  %-26s <prepare failed>\n", p); return; }
  if (sqlite3_step(s) == SQLITE_ROW) printf("  %-26s %s\n", p, sqlite3_column_text(s, 0));
  else printf("  %-26s <no row>\n", p);
  sqlite3_finalize(s);
}

int main(int argc, char **argv) {
  if (argc < 4) { fprintf(stderr, "usage: cref create|read PATH HEXKEY [sql]\n"); return 2; }
  const char *mode = argv[1], *path = argv[2], *hexkey = argv[3];
  sqlite3 *db; char pragma[256];
  if (sqlite3_open(path, &db) != SQLITE_OK) { fprintf(stderr, "open: %s\n", sqlite3_errmsg(db)); return 1; }
  snprintf(pragma, sizeof pragma, "PRAGMA key = \"x'%s'\";", hexkey);
  if (sqlite3_exec(db, pragma, 0, 0, 0) != SQLITE_OK) { fprintf(stderr, "key: %s\n", sqlite3_errmsg(db)); return 1; }

  if (!strcmp(mode, "create")) {
    /* rollback journal keeps the artifact to just the main db file */
    if (sqlite3_exec(db, "PRAGMA journal_mode=DELETE;", 0, 0, 0) != SQLITE_OK) { fprintf(stderr, "jm: %s\n", sqlite3_errmsg(db)); return 1; }
    const char *sql = argc > 4 ? argv[4] : "CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT); INSERT INTO t(v) VALUES('hello-from-c');";
    char *err = 0;
    if (sqlite3_exec(db, sql, 0, 0, &err) != SQLITE_OK) { fprintf(stderr, "sql: %s\n", err); return 1; }
    printf("created %s\n", path);
  } else {
    sqlite3_stmt *s;
    if (sqlite3_prepare_v2(db, "SELECT id, v FROM t ORDER BY id;", -1, &s, 0) != SQLITE_OK) {
      fprintf(stderr, "READ FAILED: %s\n", sqlite3_errmsg(db)); return 1;
    }
    int n = 0;
    while (sqlite3_step(s) == SQLITE_ROW) { printf("row %lld=%s\n", (long long)sqlite3_column_int64(s,0), sqlite3_column_text(s,1)); n++; }
    sqlite3_finalize(s);
    if (n == 0) { fprintf(stderr, "READ FAILED: no rows / %s\n", sqlite3_errmsg(db)); return 1; }
  }
  printf("cipher settings (library=%s):\n", sqlite3_libversion());
  const char *ps[] = {"cipher_version","cipher_page_size","kdf_iter","fast_kdf_iter","cipher_hmac_algorithm","cipher_kdf_algorithm","cipher_salt","cipher_plaintext_header_size","cipher_use_hmac",0};
  for (int i = 0; ps[i]; i++) show(db, ps[i]);
  sqlite3_close(db);
  return 0;
}
