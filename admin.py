from auth import log_audit, register_user
from database import get_connection


def get_all_users():
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT
                users.id,
                users.username,
                users.role_id,
                roles.role_name,
                users.failed_attempts,
                users.locked,
                users.created_at
            FROM users
            LEFT JOIN roles ON users.role_id = roles.id
            ORDER BY users.id
            """
        ).fetchall()


def get_user(user_id):
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT
                users.id,
                users.username,
                users.role_id,
                roles.role_name,
                users.failed_attempts,
                users.locked,
                users.created_at
            FROM users
            LEFT JOIN roles ON users.role_id = roles.id
            WHERE users.id = ?
            """,
            (user_id,),
        ).fetchone()


def get_user_by_username(username):
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT
                users.id,
                users.username,
                users.role_id,
                roles.role_name,
                users.failed_attempts,
                users.locked,
                users.created_at
            FROM users
            LEFT JOIN roles ON users.role_id = roles.id
            WHERE users.username = ?
            """,
            (username,),
        ).fetchone()


def create_user(username, password, role_id, created_by=None):
    created = register_user(username, password, role_id)

    if created:
        actor = created_by or "system"
        log_audit(actor, f"created_user:{username}")

    return created


def assign_role(user_id, role_id, assigned_by=None):
    if not role_exists(role_id):
        raise ValueError("Role does not exist.")

    with get_connection() as conn:
        cursor = conn.execute(
            """
            UPDATE users
            SET role_id = ?
            WHERE id = ?
            """,
            (role_id, user_id),
        )
        conn.commit()

    updated = cursor.rowcount > 0

    if updated:
        actor = assigned_by or "system"
        log_audit(actor, f"assigned_role:user_id={user_id}:role_id={role_id}")

    return updated


def get_all_roles():
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT id, role_name
            FROM roles
            ORDER BY role_name
            """
        ).fetchall()


def get_role(role_id):
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT id, role_name
            FROM roles
            WHERE id = ?
            """,
            (role_id,),
        ).fetchone()


def role_exists(role_id):
    return get_role(role_id) is not None


def create_role(role_name, created_by=None):
    role_name = role_name.strip()

    if not role_name:
        raise ValueError("Role name is required.")

    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT OR IGNORE INTO roles(role_name)
            VALUES (?)
            """,
            (role_name,),
        )
        conn.commit()

    created = cursor.rowcount > 0

    if created:
        actor = created_by or "system"
        log_audit(actor, f"created_role:{role_name}")

    return created


def get_all_permissions():
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT id, permission_name
            FROM permissions
            ORDER BY permission_name
            """
        ).fetchall()


def assign_permission_to_role(role_id, permission_id, assigned_by=None):
    if not role_exists(role_id):
        raise ValueError("Role does not exist.")

    if not permission_exists(permission_id):
        raise ValueError("Permission does not exist.")

    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT OR IGNORE INTO role_permissions(role_id, permission_id)
            VALUES (?, ?)
            """,
            (role_id, permission_id),
        )
        conn.commit()

    assigned = cursor.rowcount > 0

    if assigned:
        actor = assigned_by or "system"
        log_audit(
            actor,
            f"assigned_permission:role_id={role_id}:permission_id={permission_id}",
        )

    return assigned


def remove_permission_from_role(role_id, permission_id, removed_by=None):
    with get_connection() as conn:
        cursor = conn.execute(
            """
            DELETE FROM role_permissions
            WHERE role_id = ? AND permission_id = ?
            """,
            (role_id, permission_id),
        )
        conn.commit()

    removed = cursor.rowcount > 0

    if removed:
        actor = removed_by or "system"
        log_audit(
            actor,
            f"removed_permission:role_id={role_id}:permission_id={permission_id}",
        )

    return removed


def permission_exists(permission_id):
    with get_connection() as conn:
        permission = conn.execute(
            """
            SELECT id
            FROM permissions
            WHERE id = ?
            """,
            (permission_id,),
        ).fetchone()

    return permission is not None


def get_role_permissions(role_id):
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT permissions.id, permissions.permission_name
            FROM role_permissions
            JOIN permissions ON role_permissions.permission_id = permissions.id
            WHERE role_permissions.role_id = ?
            ORDER BY permissions.permission_name
            """,
            (role_id,),
        ).fetchall()


def lock_user(user_id, locked_by=None):
    with get_connection() as conn:
        cursor = conn.execute(
            """
            UPDATE users
            SET locked = 1
            WHERE id = ?
            """,
            (user_id,),
        )
        conn.commit()

    locked = cursor.rowcount > 0

    if locked:
        actor = locked_by or "system"
        log_audit(actor, f"locked_user:user_id={user_id}")

    return locked


def unlock_user(user_id, unlocked_by=None):
    with get_connection() as conn:
        cursor = conn.execute(
            """
            UPDATE users
            SET failed_attempts = 0, locked = 0
            WHERE id = ?
            """,
            (user_id,),
        )
        conn.commit()

    unlocked = cursor.rowcount > 0

    if unlocked:
        actor = unlocked_by or "system"
        log_audit(actor, f"unlocked_user:user_id={user_id}")

    return unlocked


def delete_user(user_id, deleted_by=None):
    user = get_user(user_id)

    if user is None:
        return False

    with get_connection() as conn:
        cursor = conn.execute(
            """
            DELETE FROM users
            WHERE id = ?
            """,
            (user_id,),
        )
        conn.commit()

    deleted = cursor.rowcount > 0

    if deleted:
        actor = deleted_by or "system"
        log_audit(actor, f"deleted_user:{user['username']}")

    return deleted


def get_audit_logs(limit=100):
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT id, username, action, timestamp
            FROM audit_logs
            ORDER BY timestamp DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
