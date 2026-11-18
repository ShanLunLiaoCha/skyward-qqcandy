//! What the phone's lock settings keep: a value under a name, for each
//! user. Among them is which of the protectors the phone keeps for a user
//! is the one that user's own credential opens.

use anyhow::{Context, Result};
use std::path::Path;

/// Where the phone keeps them.
pub const DATABASE: &str = "/data/system/locksettings.db";

/// The name the protector of a user's own secret is recorded under. Its
/// value is the number that protector's files are named after.
const CURRENT_PROTECTOR: &str = "sp-handle";

/// The number that names no protector. The files the phone keeps for a
/// user's secret itself, rather than for any one protector, are named
/// after it.
const NO_PROTECTOR: i64 = 0;

/// Which protector `user`'s own credential opens, named as its files are.
/// A phone that recorded none for this user gives nothing.
pub fn current_protector(database: &Path, user: u32) -> Result<Option<String>> {
    let Some(recorded) = value(database, CURRENT_PROTECTOR, user)? else { return Ok(None) };
    let id: i64 = recorded
        .parse()
        .with_context(|| format!("{} records user {user}'s protector as {recorded:?}", database.display()))?;
    Ok((id != NO_PROTECTOR).then(|| crate::user::protector_name(id)))
}

/// What the lock settings keep for `user` under `name`, where they keep
/// anything. The database is opened as it lies, without being written to
/// or waiting on anyone, since the phone it belongs to is not running; it
/// is written without a log of its own, so what it holds is all of it.
fn value(database: &Path, name: &str, user: u32) -> Result<Option<String>> {
    let at = format!("file:{}?immutable=1", database.display());
    let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI;
    let db = rusqlite::Connection::open_with_flags(&at, flags).with_context(|| format!("open {}", database.display()))?;
    value_in(&db, database, name, user)
}

fn value_in(db: &rusqlite::Connection, database: &Path, name: &str, user: u32) -> Result<Option<String>> {
    let mut query = db
        .prepare("SELECT value FROM locksettings WHERE name = ?1 AND user = ?2")
        .context("ask the lock settings what they keep")?;
    let mut rows = query
        .query((name, user))
        .with_context(|| format!("ask the lock settings what {name} is for user {user}"))?;
    let Some(row) = rows.next().with_context(|| format!("read what {} says about {name}", database.display()))? else {
        return Ok(None);
    };
    let result = row.get(0).with_context(|| format!("read what {name} is for user {user}"))?;
    anyhow::ensure!(rows.next()?.is_none(), "duplicate lock setting {name} for user {user}");
    Ok(result)
}

/// Only accept the positively identified no-lock configuration of the
/// legacy owner layout. Never treat ignored SQLite WAL state as proof.
#[cfg(any(target_os = "android", test))]
pub(crate) fn legacy_owner_has_no_lock(database: &Path) -> Result<bool> {
    if !std::fs::symlink_metadata(database)?.is_file() { return Ok(false); }
    for suffix in ["-wal", "-journal"] {
        let mut name = database.as_os_str().to_owned();
        name.push(suffix);
        match std::fs::symlink_metadata(name) {
            Ok(meta) if !meta.is_file() || meta.len() != 0 => return Ok(false),
            Ok(_) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    let at = format!("file:{}?immutable=1", database.display());
    let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI;
    let db = rusqlite::Connection::open_with_flags(&at, flags)?;
    let mut query = db.prepare("SELECT name, value FROM locksettings WHERE user = 0 AND name IN ('sp-handle', 'enable-sp', 'lockscreen.password_type', 'lockscreen.password_type_alternate')")?;
    let mut rows = query.query(())?;
    let mut alternate_seen = false;
    while let Some(row) = rows.next()? {
        let name: String = row.get(0)?;
        let value: Option<String> = row.get(1)?;
        if name != "lockscreen.password_type_alternate" || alternate_seen || value.as_deref() != Some("0") { return Ok(false); }
        alternate_seen = true;
    }
    Ok(alternate_seen)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lock settings as the phone writes them: the table it keeps, holding
    /// the rows given.
    fn scratch(test: &str, rows: &[(&str, u32, Option<&str>)]) -> std::path::PathBuf {
        let at = std::env::temp_dir().join(format!("skyward-locksettings-{test}-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&at);
        let db = rusqlite::Connection::open(&at).unwrap();
        db.execute("CREATE TABLE locksettings (_id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, user INTEGER, value TEXT)", ()).unwrap();
        for (name, user, value) in rows {
            db.execute("INSERT INTO locksettings (name, user, value) VALUES (?1, ?2, ?3)", (name, user, value)).unwrap();
        }
        at
    }

    #[test]
    fn legacy_owner_accepts_only_a16_no_lock_records() {
        let state = ("lockscreen.password_type_alternate", 0, Some("0"));
        let variants = [
            (vec![state], true),
            (vec![], false),
            (vec![state, ("sp-handle", 0, Some("42"))], false),
            (vec![state, ("enable-sp", 0, Some("true"))], false),
            (vec![state, ("lockscreen.password_type", 0, Some("131072"))], false),
            (vec![state, state], false),
            (vec![("lockscreen.password_type_alternate", 0, Some("131072"))], false),
        ];
        for (i, (rows, expected)) in variants.into_iter().enumerate() {
            let db = scratch(&format!("a16-no-lock-{i}"), &rows);
            assert_eq!(legacy_owner_has_no_lock(&db).unwrap(), expected);
            if expected {
                let wal = db.with_extension("db-wal");
                std::fs::write(&wal, b"unapplied state").unwrap();
                assert!(!legacy_owner_has_no_lock(&db).unwrap());
                std::fs::remove_file(wal).unwrap();
            }
            std::fs::remove_file(db).unwrap();
        }
    }

    #[test]
    fn the_protector_recorded_for_a_user_is_the_one_named() {
        let at = scratch("recorded", &[
            ("sp-handle", 0, Some("623346955855960006")),
            ("sp-handle", 10, Some("-1")),
            ("lockscreen.password_type", 0, Some("65536")),
        ]);
        assert_eq!(current_protector(&at, 0).unwrap().as_deref(), Some("08a692c0f39d97c6"));
        assert_eq!(current_protector(&at, 10).unwrap().as_deref(), Some("ffffffffffffffff"));
        assert_eq!(current_protector(&at, 11).unwrap(), None, "a user the phone recorded nothing for");
        std::fs::remove_file(&at).unwrap();
    }

    #[test]
    fn the_number_of_no_protector_and_a_row_holding_nothing_give_none() {
        let at = scratch("none", &[("sp-handle", 0, Some("0")), ("sp-handle", 10, None)]);
        assert_eq!(current_protector(&at, 0).unwrap(), None);
        assert_eq!(current_protector(&at, 10).unwrap(), None, "a row holding nothing");
        std::fs::remove_file(&at).unwrap();
    }

    #[test]
    fn a_value_that_is_no_number_and_a_database_that_is_not_there_are_errors() {
        let at = scratch("odd", &[("sp-handle", 0, Some("behind the sofa"))]);
        assert!(current_protector(&at, 0).is_err());
        assert!(current_protector(Path::new("/nowhere/locksettings.db"), 0).is_err());
        std::fs::remove_file(&at).unwrap();
    }
}
