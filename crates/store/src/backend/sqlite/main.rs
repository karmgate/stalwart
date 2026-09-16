/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{SqliteStore, into_error, pool::SqliteConnectionManager};
use crate::*;
use ::registry::schema::structs;
use r2d2::Pool;
use tokio::sync::oneshot;

/// Environment variable that carries the optional SQLCipher raw key.
///
/// ArmoredPost private-fork knob. Kept as an env var (rather than a Stalwart
/// config field) so the encrypted-at-rest behaviour stays a drop-in overlay
/// over the upstream plain-SQLite store: unset/empty == byte-for-byte upstream.
/// See the module design note for the path to upstreaming this as a proper
/// `encryption_key` / `key_env` store config field.
const SQLCIPHER_KEY_ENV: &str = "VOLT_SQLCIPHER_KEY";

/// Validate a SQLCipher raw key and return the connection-init SQL to apply it.
///
/// The key must be **exactly 64 lowercase-hex characters** (32 bytes). This is
/// the raw-key `x'...'` form, which skips the KDF, so a malformed or short key
/// would otherwise be silently accepted by SQLCipher and derive a *different*
/// key — the #206 silent-divergence class (a wrong key can create a brand-new
/// empty encrypted DB rather than failing loudly). Rejecting anything that is
/// not 64 lowercase-hex chars up front also closes the format-string injection
/// surface: without this check a key containing `'` or `;` (a misconfig) would
/// break out of the `x'...'` literal and run arbitrary PRAGMA/SQL as the first
/// statement on every connection.
///
/// Returns:
/// - `Ok(None)`   — no key configured (env unset/empty); store behaves as
///   upstream plain SQLite.
/// - `Ok(Some(sql))` — validated key; `sql` is the `PRAGMA key` statement.
/// - `Err(msg)`   — a key was supplied but is malformed; fail fast.
fn resolve_sqlcipher_pragma(raw: Option<&str>) -> Result<Option<String>, String> {
    let key = match raw {
        Some(k) if !k.is_empty() => k,
        _ => return Ok(None),
    };

    if key.len() != 64
        || !key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(format!(
            "{SQLCIPHER_KEY_ENV} must be exactly 64 lowercase-hex characters \
             (a 32-byte raw SQLCipher key); got {} character(s). Refusing to \
             open the store with a malformed key to avoid silent data \
             divergence.",
            key.len()
        ));
    }

    // Safe to interpolate: `key` is now guaranteed to be 64 lowercase-hex
    // chars, so it cannot contain a quote/semicolon or otherwise escape the
    // x'...' literal.
    Ok(Some(format!("PRAGMA key = \"x'{key}'\";")))
}

impl SqliteStore {
    pub fn open(config: structs::SqliteStore) -> Result<Store, String> {
        // ArmoredPost: optional SQLCipher encryption of the data store.
        // Validate the key ONCE, up front, so a malformed key fails the whole
        // open() with a clear message (instead of an opaque per-connection
        // pool error). If no key is configured this is a no-op and the store
        // behaves exactly as upstream (plain SQLite). Requires building the
        // `store` crate with the rusqlite
        // `bundled-sqlcipher[-vendored-openssl]` feature.
        let key_pragma =
            resolve_sqlcipher_pragma(std::env::var(SQLCIPHER_KEY_ENV).ok().as_deref())?;

        Ok(Store::SQLite(Arc::new(SqliteStore {
            conn_pool: Pool::builder()
                .max_size(config.pool_max_connections as u32)
                .build(
                    SqliteConnectionManager::file(&config.path).with_init(move |c| {
                        // The key PRAGMA MUST be the first statement on the
                        // connection, before journal_mode etc.
                        if let Some(pragma) = key_pragma.as_deref() {
                            c.execute_batch(pragma)?;

                            // Confirm the key actually decrypted the DB. Without
                            // this probe a wrong key surfaces later as opaque
                            // "file is not a database" errors on the first real
                            // query; here it fails fast on connection init.
                            c.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
                                .map_err(|e| {
                                    rusqlite::Error::SqliteFailure(
                                        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_NOTADB),
                                        Some(format!(
                                            "SQLCipher could not decrypt the data \
                                         store with the supplied \
                                         {SQLCIPHER_KEY_ENV}: {e}"
                                        )),
                                    )
                                })?;
                        }
                        c.execute_batch(concat!(
                            "PRAGMA journal_mode = WAL; ",
                            "PRAGMA synchronous = NORMAL; ",
                            "PRAGMA temp_store = memory;",
                            "PRAGMA busy_timeout = 30000;"
                        ))
                    }),
                )
                .map_err(|err| format!("Failed to build connection pool: {err}"))?,
            worker_pool: rayon::ThreadPoolBuilder::new()
                .num_threads(std::cmp::max(
                    config
                        .pool_workers
                        .filter(|v| *v > 0)
                        .map(|v| v as usize)
                        .unwrap_or_else(num_cpus::get),
                    4,
                ))
                .build()
                .map_err(|err| format!("Failed to build worker pool: {err}"))?,
        })))
    }

    #[cfg(feature = "test_mode")]
    pub fn open_memory() -> trc::Result<Self> {
        use super::into_error;

        let db = Self {
            conn_pool: Pool::builder()
                .max_size(1)
                .build(SqliteConnectionManager::memory())
                .map_err(into_error)?,
            worker_pool: rayon::ThreadPoolBuilder::new()
                .num_threads(num_cpus::get())
                .build()
                .map_err(|err| {
                    into_error(err).ctx(trc::Key::Reason, "Failed to build worker pool")
                })?,
        };
        db.create_tables()?;
        Ok(db)
    }

    pub(crate) fn create_tables(&self) -> trc::Result<()> {
        let conn = self.conn_pool.get().map_err(into_error)?;

        for table in [
            SUBSPACE_ACL,
            SUBSPACE_TASK_QUEUE,
            SUBSPACE_DELETED_ITEMS,
            SUBSPACE_SPAM_SAMPLES,
            SUBSPACE_BLOB_LINK,
            SUBSPACE_IN_MEMORY_VALUE,
            SUBSPACE_PROPERTY,
            SUBSPACE_REGISTRY,
            SUBSPACE_REGISTRY_PK,
            SUBSPACE_QUEUE_MESSAGE,
            SUBSPACE_QUEUE_EVENT,
            SUBSPACE_REPORT_OUT,
            SUBSPACE_REPORT_IN,
            SUBSPACE_LOGS,
            SUBSPACE_BLOBS,
            SUBSPACE_TELEMETRY_SPAN,
            SUBSPACE_TELEMETRY_METRIC,
            SUBSPACE_SEARCH_INDEX,
            SUBSPACE_DIRECTORY,
        ] {
            let table = char::from(table);
            conn.execute(
                &format!(
                    "CREATE TABLE IF NOT EXISTS {table} (
                        k BLOB PRIMARY KEY,
                        v BLOB NOT NULL
                    )"
                ),
                [],
            )
            .map_err(into_error)?;
        }

        for table in [SUBSPACE_INDEXES, SUBSPACE_REGISTRY_IDX] {
            let table = char::from(table);
            conn.execute(
                &format!(
                    "CREATE TABLE IF NOT EXISTS {table} (
                        k BLOB PRIMARY KEY
                )"
                ),
                [],
            )
            .map_err(into_error)?;
        }

        for table in [SUBSPACE_COUNTER, SUBSPACE_QUOTA, SUBSPACE_IN_MEMORY_COUNTER] {
            conn.execute(
                &format!(
                    "CREATE TABLE IF NOT EXISTS {} (
                    k BLOB PRIMARY KEY,
                    v INTEGER NOT NULL DEFAULT 0
                )",
                    char::from(table)
                ),
                [],
            )
            .map_err(into_error)?;
        }

        Ok(())
    }

    pub async fn spawn_worker<U, V>(&self, mut f: U) -> trc::Result<V>
    where
        U: FnMut() -> trc::Result<V> + Send,
        V: Sync + Send + 'static,
    {
        let (tx, rx) = oneshot::channel();

        self.worker_pool.scope(|s| {
            s.spawn(|_| {
                tx.send(f()).ok();
            });
        });

        match rx.await {
            Ok(result) => result,
            Err(err) => Err(trc::EventType::Server(trc::ServerEvent::ThreadError).reason(err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn key_validation_accepts_64_lower_hex() {
        let pragma = resolve_sqlcipher_pragma(Some(GOOD_KEY))
            .expect("64-hex key should validate")
            .expect("a key was supplied, expected a pragma");
        assert_eq!(pragma, format!("PRAGMA key = \"x'{GOOD_KEY}'\";"));
    }

    #[test]
    fn no_key_is_a_noop() {
        assert!(resolve_sqlcipher_pragma(None).unwrap().is_none());
        assert!(resolve_sqlcipher_pragma(Some("")).unwrap().is_none());
    }

    #[test]
    fn key_validation_rejects_wrong_length() {
        // Too short.
        assert!(resolve_sqlcipher_pragma(Some("0123456789abcdef")).is_err());
        // Too long (65 chars).
        assert!(resolve_sqlcipher_pragma(Some(&format!("{GOOD_KEY}a"))).is_err());
    }

    #[test]
    fn key_validation_rejects_non_hex_and_uppercase() {
        // 64 chars but contains a non-hex char.
        let with_g = format!("g{}", &GOOD_KEY[1..]);
        assert!(resolve_sqlcipher_pragma(Some(&with_g)).is_err());
        // 64 chars but uppercase (raw x'...' form is case-sensitive here; we
        // require lowercase so the value is deterministic).
        assert!(resolve_sqlcipher_pragma(Some(&GOOD_KEY.to_uppercase())).is_err());
    }

    #[test]
    fn key_validation_closes_injection_surface() {
        // A key that tries to break out of the x'...' literal and run extra
        // SQL must be rejected outright (it is not 64 lowercase-hex chars).
        let inject = "0123456789abcdef0123456789abcdef'; DROP TABLE x;--abcdef01";
        let err = resolve_sqlcipher_pragma(Some(inject)).unwrap_err();
        assert!(err.contains(SQLCIPHER_KEY_ENV));
    }

    // Exercises the real encrypted path (PRAGMA key + decrypt probe) against a
    // SQLCipher-backed rusqlite connection, mirroring what the store's
    // connection-init closure does. Requires the rusqlite
    // `bundled-sqlcipher[-vendored-openssl]` feature (enabled by the `sqlite`
    // store feature that gates this whole file).
    fn open_keyed(path: &std::path::Path, key: &str) -> Result<rusqlite::Connection, String> {
        let pragma = resolve_sqlcipher_pragma(Some(key))?.unwrap();
        let conn = rusqlite::Connection::open(path).map_err(|e| e.to_string())?;
        conn.execute_batch(&pragma).map_err(|e| e.to_string())?;
        // Same fail-fast decrypt probe as the store init closure.
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
            .map_err(|e| format!("decrypt probe failed: {e}"))?;
        Ok(conn)
    }

    #[test]
    fn encrypted_file_roundtrip_good_and_bad_key() {
        let dir = std::env::temp_dir().join(format!("sqlcipher-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("enc.db");
        let _ = std::fs::remove_file(&path);

        let good = GOOD_KEY;
        let wrong = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

        // Create + write with the good key.
        {
            let conn = open_keyed(&path, good).expect("create with good key");
            conn.execute_batch("CREATE TABLE t (v INTEGER); INSERT INTO t VALUES (42);")
                .unwrap();
        }

        // Reopen with the good key: probe passes, data readable.
        {
            let conn = open_keyed(&path, good).expect("reopen with good key");
            let v: i64 = conn.query_row("SELECT v FROM t", [], |r| r.get(0)).unwrap();
            assert_eq!(v, 42);
        }

        // Reopen with a wrong key: the decrypt probe must fail fast, NOT
        // silently open an empty/divergent DB.
        let err = open_keyed(&path, wrong).expect_err("wrong key must fail");
        assert!(err.contains("decrypt probe failed"), "unexpected: {err}");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }
}
