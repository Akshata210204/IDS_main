from database import get_connection

# ================= ADMIN CREDENTIALS =================
ADMIN_EMAIL = "admin@ids.com"
ADMIN_PASSWORD = "admin123"

# =====================================================
def register_user(email, password):
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (email, password, role) VALUES (?, ?, ?)",
            (email, password, "user")
        )
        conn.commit()
        return True
    except:
        return False
    finally:
        conn.close()


# =====================================================
def login_user(email, password):

    # ADMIN (hardcoded, NOT in DB)
    if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
        return "admin"

    # USER
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "SELECT password, role, status FROM users WHERE email=?",
        (email,)
    )

    row = cur.fetchone()
    conn.close()

    if row is None:
        return "not_found"

    db_password, role, status = row

    if password != db_password:
        return None

    if status == "blocked":
        return "blocked"

    return role
