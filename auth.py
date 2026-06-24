from sqlite3 import IntegrityError

from flask_bcrypt import Bcrypt

from database import get_connection


bcrypt = Bcrypt()

MAX_FAILED_ATTEMPTS = 5
MIN_PASSWORD_LENGTH = 8


def log_audit(username, action):
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO audit_logs(username, action) VALUES (?, ?)",
            (username, action),
        )
        conn.commit()


def is_strong_password(password):
    if len(password) < MIN_PASSWORD_LENGTH:
        return False

    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_symbol = any(not char.isalnum() for char in password)

    return has_upper and has_lower and has_digit and has_symbol


def get_user_by_username(username):
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT
                users.id,
                users.username,
                users.password_hash,
                users.role_id,
                users.failed_attempts,
                users.locked,
                roles.role_name
            FROM users
            LEFT JOIN roles ON users.role_id = roles.id
            WHERE users.username = ?
            """,
            (username,),
        ).fetchone()


def register_user(username, password, role_id):
    username = username.strip()

    if not username:
        raise ValueError("Username is required.")

    if not is_strong_password(password):
        raise ValueError(
            "Password must be at least 8 characters and include uppercase, "
            "lowercase, number, and symbol characters."
        )

    password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    try:
        with get_connection() as conn:
            conn.execute(
                """
                INSERT INTO users(username, password_hash, role_id)
                VALUES (?, ?, ?)
                """,
                (username, password_hash, role_id),
            )
            conn.commit()

        log_audit(username, "user_registered")
        return True
    except IntegrityError:
        return False


def authenticate_user(username, password):
    user = get_user_by_username(username)

    if user is None:
        log_audit(username, "login_failed_unknown_user")
        return False, "Invalid username or password."

    if user["locked"]:
        log_audit(username, "login_failed_account_locked")
        return False, "Account is locked."

    if bcrypt.check_password_hash(user["password_hash"], password):
        with get_connection() as conn:
            conn.execute(
                """
                UPDATE users
                SET failed_attempts = 0
                WHERE username = ?
                """,
                (username,),
            )
            conn.commit()

        log_audit(username, "login_success")
        return True, "Login successful."

    failed_attempts = user["failed_attempts"] + 1
    locked = 1 if failed_attempts >= MAX_FAILED_ATTEMPTS else 0

    with get_connection() as conn:
        conn.execute(
            """
            UPDATE users
            SET failed_attempts = ?, locked = ?
            WHERE username = ?
            """,
            (failed_attempts, locked, username),
        )
        conn.commit()

    action = "login_failed_account_locked" if locked else "login_failed"
    log_audit(username, action)

    return False, "Invalid username or password."


def user_has_permission(username, permission_name):
    with get_connection() as conn:
        permission = conn.execute(
            """
            SELECT 1
            FROM users
            JOIN role_permissions ON users.role_id = role_permissions.role_id
            JOIN permissions ON role_permissions.permission_id = permissions.id
            WHERE users.username = ?
              AND permissions.permission_name = ?
              AND users.locked = 0
            """,
            (username, permission_name),
        ).fetchone()

    return permission is not None


def unlock_user(username):
    with get_connection() as conn:
        cursor = conn.execute(
            """
            UPDATE users
            SET failed_attempts = 0, locked = 0
            WHERE username = ?
            """,
            (username,),
        )
        conn.commit()

    if cursor.rowcount:
        log_audit(username, "account_unlocked")
        return True

    return False


def change_password(username, current_password, new_password):
    user = get_user_by_username(username)

    if user is None:
        return False, "User not found."

    if not bcrypt.check_password_hash(user["password_hash"], current_password):
        log_audit(username, "password_change_failed")
        return False, "Current password is incorrect."

    if not is_strong_password(new_password):
        return False, (
            "Password must be at least 8 characters and include uppercase, "
            "lowercase, number, and symbol characters."
        )

    password_hash = bcrypt.generate_password_hash(new_password).decode("utf-8")

    with get_connection() as conn:
        conn.execute(
            """
            UPDATE users
            SET password_hash = ?
            WHERE username = ?
            """,
            (password_hash, username),
        )
        conn.commit()

    log_audit(username, "password_changed")
    return True, "Password changed successfully."
