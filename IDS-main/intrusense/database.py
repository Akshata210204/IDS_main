
import sqlite3

def get_connection():
    return sqlite3.connect("users.db", check_same_thread=False)

# ---------------- DETECTION LOGS ----------------
def create_detection_logs_table():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS detection_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            filename TEXT,
            detection_type TEXT,
            total_records INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()

# ---------------- SYSTEM CONTROLS ----------------
def create_system_controls_table():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS system_controls (
            feature TEXT PRIMARY KEY,
            status TEXT
        )
    """)

    # default values (run once)
    cur.execute("INSERT OR IGNORE INTO system_controls VALUES ('live_detection','ON')")
    cur.execute("INSERT OR IGNORE INTO system_controls VALUES ('file_upload','ON')")
    cur.execute("INSERT OR IGNORE INTO system_controls VALUES ('detection_page','ON')")

    conn.commit()
    conn.close()



def insert_detection_log(email, filename, detection_type, total_records):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO detection_logs
        (email, filename, detection_type, total_records)
        VALUES (?, ?, ?, ?)
    """, (email, filename, detection_type, total_records))

    conn.commit()
    conn.close()

def get_detection_logs():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT email, filename, detection_type, total_records, timestamp
        FROM detection_logs
        ORDER BY timestamp DESC
    """)

    logs = cur.fetchall()
    conn.close()
    return logs


def get_all_users():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, email, role FROM users
    """)

    users = cur.fetchall()
    conn.close()
    return users


def create_users_table():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password TEXT,
            role TEXT,
            status TEXT DEFAULT 'active'
        )
    """)

    conn.commit()
    conn.close()


def get_all_users():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "SELECT id, email, role, status FROM users WHERE role != 'admin'"
    )

    users = cur.fetchall()
    conn.close()
    return users


def delete_user(user_id):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "DELETE FROM users WHERE id = ?",
        (user_id,)
    )

    conn.commit()
    conn.close()




def block_user(user_id):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        UPDATE users
        SET status = 'blocked'
        WHERE id = ? AND role = 'user'
    """, (user_id,))

    conn.commit()
    conn.close()


def unblock_user(user_id):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        UPDATE users
        SET status = 'active'
        WHERE id = ? AND role = 'user'
    """, (user_id,))

    conn.commit()
    conn.close()



# ================= UPDATE USER STATUS =================
def update_user_status(user_id, status):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "UPDATE users SET status = ? WHERE id = ?",
        (status, user_id)
    )

    conn.commit()
    conn.close()



def add_status_column():
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'active'"
        )
        conn.commit()
    except:
        pass
    conn.close()

def get_all_users():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "SELECT id, email, role, status FROM users WHERE role != 'admin'"
    )

    users = cur.fetchall()
    conn.close()
    return users

