# havuz JDBC agent

A JVM process that havuz drives over stdin/stdout to reach databases that have
no Rust driver and no wire protocol anyone wants to reimplement — Oracle, DB2,
Informix, Snowflake, Teradata, and the rest of the long tail.

It is deliberately small and has **no dependencies**. The message shapes are
fixed and narrow, so a hand-written JSON reader and writer is about 250 lines
and removes Maven, Gradle and a dependency tree from the build. Building it is
`javac` and `jar`, nothing else.

## Protocol

Newline-delimited JSON-RPC 2.0 over stdio, exactly one JSON document per line.
On startup the agent prints a bare readiness line before anything else, so the
parent can tell "JVM still booting" from "JVM is wedged":

```
{"ready":true,"protocol":1}
```

Then requests and responses:

```
--> {"jsonrpc":"2.0","id":1,"method":"open_session","params":{"url":"jdbc:postgresql://…","user":"app","password":"…"}}
<-- {"jsonrpc":"2.0","id":1,"result":{"session":"s1","serverVersion":"16.2","inTransaction":false}}
```

Responses may arrive out of order; the parent demultiplexes on `id`.

### Methods

| Method | Params | Result |
|---|---|---|
| `handshake` | — | `{protocol, java, vendor}` |
| `open_session` | `url, user, password, driverClass?, driverPaths?, connectTimeoutMs?` | `{session, serverVersion, inTransaction}` |
| `execute` | `session, sql, params?, maxRows?` | see below |
| `prepare` | `session, sql` | `{columns, paramCount}` |
| `reset` | `session` | `{inTransaction}` |
| `close_session` | `session` | `{}` |
| `shutdown` | — | `{}` |

`execute` returns:

```json
{
  "columns": [{"name": "id", "jdbcType": 4, "typeName": "int4", "precision": 10, "scale": 0}],
  "rows": [["1"], [null]],
  "updateCount": -1,
  "command": "SELECT",
  "inTransaction": false
}
```

### Where the type mapping lives, and why

The agent turns every value into **a canonical string or null**, and reports the
JDBC type alongside. It does *not* know what a PostgreSQL type OID is.

That split is deliberate. Deciding that `java.sql.Types.NUMERIC` is canonically
`"12.50"` needs `ResultSetMetaData` and a `BigDecimal`, which exist here.
Deciding that it is OID 1700 and that a boolean is spelled `t` needs to know
which wire protocol the client is speaking, which does not exist here and may
not be PostgreSQL forever.

`BigDecimal` is rendered with `toPlainString`, never as a JSON number: a JSON
number is a double once parsed, and a `NUMERIC(38,10)` is not.

Binary is hex without a prefix. The frontend adds whatever its protocol wants.

## Building

The build runs in a container so no JDK has to be installed:

```sh
./agent/build.sh              # -> agent/build/havuz-agent.jar
```

Running it only needs a JRE 17 or newer on `PATH`. havuz reports a clear error
when there is none, rather than failing on the first connection.
