from database import get_connection
import re

# ================= EMAIL VALIDATION =================
def is_valid_gmail(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@gmail\.com$'
    return re.match(pattern, email) is not None


# ================= ADMIN CREDENTIALS =================
ADMIN_EMAIL = "admin@ids.com"
ADMIN_PASSWORD = "admin123"
# =====================================================


# ================= REGISTER FUNCTION =================
def register_user(email, password):

    # Check Gmail format
    if not is_valid_gmail(email):
        return "invalid_email"

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


# ================= LOGIN FUNCTION =================
def login_user(email, password):

    # Validate Gmail for normal users (not admin)
    if email != ADMIN_EMAIL and not is_valid_gmail(email):
        return "invalid_email"

    # ===== ADMIN LOGIN (Hardcoded) =====
    if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
        return "admin"

    # ===== USER LOGIN (Database) =====
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
