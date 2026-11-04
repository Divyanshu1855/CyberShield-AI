
import sqlite3
from werkzeug.security import generate_password_hash

DATABASE = "scans.db"


def get_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()

    # Users table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Scans table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            url TEXT NOT NULL,
            result TEXT NOT NULL,
            score INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()

    print("SQLite database initialized successfully!")


def create_user(name, email, password_hash):
    conn = get_connection()

    try:
        conn.execute("""
            INSERT INTO users (name, email, password)
            VALUES (?, ?, ?)
        """, (name, email, password_hash))

        conn.commit()
        return True

    except sqlite3.IntegrityError:
        return False

    finally:
        conn.close()


def get_user(email):
    conn = get_connection()

    user = conn.execute("""
        SELECT * FROM users WHERE email = ?
    """, (email,)).fetchone()

    conn.close()
    return user


def save_scan(user_id, url, result, score):
    conn = get_connection()

    conn.execute("""
        INSERT INTO scans (user_id, url, result, score)
        VALUES (?, ?, ?, ?)
    """, (user_id, url, result, score))

    conn.commit()
    conn.close()


def get_user_scans(user_id):
    conn = get_connection()

    history = conn.execute("""
        SELECT * FROM scans
        WHERE user_id = ?
        ORDER BY created_at DESC
    """, (user_id,)).fetchall()

    conn.close()
    return history


def get_total_users():
    conn = get_connection()
    total = conn.execute(
        "SELECT COUNT(*) FROM users"
    ).fetchone()[0]
    conn.close()
    return total


def get_total_scans():
    conn = get_connection()
    total = conn.execute(
        "SELECT COUNT(*) FROM scans"
    ).fetchone()[0]
    conn.close()
    return total


if __name__ == "__main__":
    init_db()
