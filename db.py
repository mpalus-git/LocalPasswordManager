import sqlite3
from datetime import datetime


def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS master_config (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            salt BLOB NOT NULL,
            verification_token BLOB NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_name TEXT NOT NULL,
            username TEXT NOT NULL,
            encrypted_password BLOB NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(service_name, username)
        )
    """)
    conn.commit()
    return conn


def is_master_set(conn: sqlite3.Connection) -> bool:
    cursor = conn.execute("SELECT COUNT(*) FROM master_config")
    return cursor.fetchone()[0] > 0


def save_master_config(conn: sqlite3.Connection, salt: bytes, token: bytes) -> None:
    conn.execute(
        "INSERT INTO master_config (id, salt, verification_token) VALUES (1, ?, ?)",
        (salt, token),
    )
    conn.commit()


def get_master_config(conn: sqlite3.Connection) -> tuple[bytes, bytes]:
    cursor = conn.execute(
        "SELECT salt, verification_token FROM master_config WHERE id = 1"
    )
    row = cursor.fetchone()
    if row is None:
        raise ValueError("Master Password nie został skonfigurowany.")
    return row[0], row[1]


def add_password(
    conn: sqlite3.Connection,
    service_name: str,
    username: str,
    encrypted_password: bytes,
) -> bool:
    try:
        conn.execute(
            """INSERT INTO passwords (service_name, username, encrypted_password, created_at)
               VALUES (?, ?, ?, ?)""",
            (service_name, username, encrypted_password, datetime.now().isoformat()),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False


def update_password(
    conn: sqlite3.Connection,
    service_name: str,
    username: str,
    encrypted_password: bytes,
) -> None:
    conn.execute(
        """UPDATE passwords
           SET encrypted_password = ?, created_at = ?
           WHERE service_name = ? AND username = ?""",
        (encrypted_password, datetime.now().isoformat(), service_name, username),
    )
    conn.commit()


def get_password(
    conn: sqlite3.Connection, service_name: str, username: str
) -> bytes | None:
    cursor = conn.execute(
        "SELECT encrypted_password FROM passwords WHERE service_name = ? AND username = ?",
        (service_name, username),
    )
    row = cursor.fetchone()
    return row[0] if row else None


def list_services(conn: sqlite3.Connection) -> list[tuple[str, str, str]]:
    cursor = conn.execute(
        "SELECT service_name, username, created_at FROM passwords ORDER BY service_name, username"
    )
    return cursor.fetchall()


def search_services(
    conn: sqlite3.Connection, query: str
) -> list[tuple[str, str, str]]:
    cursor = conn.execute(
        """SELECT service_name, username, created_at FROM passwords
           WHERE service_name LIKE ?
           ORDER BY service_name, username""",
        (f"%{query}%",),
    )
    return cursor.fetchall()


def delete_password(
    conn: sqlite3.Connection, service_name: str, username: str
) -> bool:
    cursor = conn.execute(
        "DELETE FROM passwords WHERE service_name = ? AND username = ?",
        (service_name, username),
    )
    conn.commit()
    return cursor.rowcount > 0
