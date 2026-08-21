# doltera

Jolt bindings for [Dolt](https://github.com/dolthub/dolt) — a MySQL-protocol
client in pure jolt (Clojure on Chez Scheme, no JVM). Speaks directly to
`dolt sql-server` over TCP: handshake, `mysql_native_password` auth (with a
from-scratch SHA-1), packet framing, text and binary result sets, and prepared
statements.

## Quick start

Start a server (see the test file for the full setup):

```sh
dolt init
dolt sql-server --port 3306
```

Then:

```clojure
(require '[doltera.core :as dolt])

(def conn (dolt/connect {:port 3306 :db "mydb"}))

(dolt/execute! conn "create table person (id int primary key, name varchar(100), zip int)")
(dolt/execute! conn "insert into person values (1, 'ada', 94546)")

(dolt/query conn "select * from person")
;; => [{:id 1, :name "ada", :zip 94546}]

(dolt/query conn ["select * from person where name = ?" "ada"]) ; params
(dolt/fetch-one conn "select count(*) from person")

;; dolt version control, straight from SQL
(dolt/dolt-commit conn "add person table")
(dolt/dolt-log conn)
```

## Types

Queries take a string or a sqlvec (`[sql & params]`, `?` placeholders). Every
statement goes through the binary (prepared) protocol, so results come back
typed:

- integers → `long`, honouring the column's unsigned flag; `bigint unsigned`
  above 2^63 promotes to a bignum
- floats → `double`, NULL → `nil`, VARCHAR/TEXT/JSON/ENUM/SET → string
- DECIMAL, DATE, DATETIME, TIME, TIMESTAMP → string (`"12.50"`,
  `"2024-01-02 03:04:05"`); fractional seconds appear when the column declares a
  precision or the value carries them
- YEAR → `long`, BIT → `long` (bignum past 2^63)
- BLOB, BINARY, VARBINARY and spatial values → byte array

Dolt reports string literals as BLOB-typed columns in the binary protocol, so
the type alone can't tell text from bytes. doltera decodes a value as text
unless its column carries the binary charset (63), which is what makes a column
genuinely binary.

## API

- `(connect opts)` — `:host` (default 127.0.0.1), `:port` (3306), `:user`
  (`root`), `:password` (`""`), `:db`. The database is selected during the
  handshake, so an unknown one is rejected at connect time.
- `(close conn)`
- `(query conn sql)` — vector of row maps
- `(execute! conn sql)` — affected rows
- `(fetch conn sql)` / `(fetch-one conn sql)` — query / first row
- `(transaction conn f)` — `start transaction` / `commit`, rollback on throw
- `(dolt-commit conn msg)` / `(dolt-branch conn name)` / `(dolt-checkout conn name)`
- `(dolt-status conn)` / `(dolt-log conn)` — Dolt 2.x table functions

`doltera.protocol` exposes the raw protocol layer (`open-conn`, `handshake!`,
`query-text`, `prepare-stmt`, `execute-stmt`, `clear-stmt-cache!`, ...) for
lower-level use.

## Tests

The wire-protocol checks run against captured packets and need no server. The
rest spawn a fresh `dolt sql-server` on a free port against a temp repo — 63
checks in total. Set `DOLTERA_TEST_PORT`, `DOLTERA_TEST_DB` and optionally
`DOLTERA_TEST_DATA_DIR` to run against an already-running server instead; the
suite creates its own tables, so point it at an empty database.

```sh
jolt -M:test
```

## Notes

- Auth is `mysql_native_password` only. Dolt's users default to it; one created
  with `IDENTIFIED WITH caching_sha2_password` just gets `Access denied`, since
  dolt denies rather than asking the client to switch plugins. A server that
  does ask gets a clear error naming the plugin.
- The connection asks for `utf8mb4`, and decodes every result as UTF-8.
- Each connection prepares a statement once and reuses it, which roughly halves
  the cost of a repeated query. The cache holds 64 statements and evicts the
  least recently used; `select-db!` clears it, since SQL text only picks out the
  same statement within one database.
- `use` is not accepted as a prepared statement, so `select-db!` (for switching
  databases mid-connection) goes through the text protocol.
- `dolt_commit` needs `-A` (stage all, incl. new tables) or an explicit
  `dolt_add` — working-set changes alone yield "nothing to commit".
