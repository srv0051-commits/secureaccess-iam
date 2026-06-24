import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DB_NAME = BASE_DIR / "users.db"

ROLES = ["Admin", "HR", "Finance", "Employee"]

PERMISSIONS = [
    "create_user",
    "delete_user",
    "view_records",
    "edit_records",
    "view_logs",
]

ROLE_PERMISSIONS = {
    "Admin":[
        "create_user",
        "delete_user",
        "view_records",
        "edit_records",
        "view_logs"
    ],

    "HR":[
        "create_user",
        "view_records",
        "edit_records"
    ],

    "Finance":[
        "create_user",
        "view_records",
        "edit_records"
    ],

    "Employee":[
        "create_user",
        "view_records"
    ]
}

def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def execute_query(query, params=(), fetch_one=False, fetch_all=False):
    with get_connection() as conn:
        cursor = conn.execute(query, params)

        if fetch_one:
            return cursor.fetchone()

        if fetch_all:
            return cursor.fetchall()

        conn.commit()
        return cursor.rowcount


def initialize_database():
    with get_connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                role_name TEXT UNIQUE NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role_id INTEGER,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked INTEGER NOT NULL DEFAULT 0 CHECK (locked IN (0, 1)),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                permission_name TEXT UNIQUE NOT NULL
            );

            CREATE TABLE IF NOT EXISTS role_permissions (
                role_id INTEGER NOT NULL,
                permission_id INTEGER NOT NULL,
                PRIMARY KEY (role_id, permission_id),
                FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE,
                FOREIGN KEY(permission_id) REFERENCES permissions(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                action TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            );
	    CREATE TABLE IF NOT EXISTS messages(
    	    	id INTEGER PRIMARY KEY AUTOINCREMENT,
    		sender TEXT NOT NULL,
   		receiver TEXT NOT NULL,
   	 	message TEXT NOT NULL,
    		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	    );
            """
        )

        run_migrations(conn)
        seed_roles(conn)
        seed_permissions(conn)
        seed_role_permissions(conn)
        conn.commit()


def run_migrations(conn):
    ensure_column(
        conn,
        "users",
        "created_at",
        "created_at DATETIME",
    )

    conn.execute(
        """
        UPDATE users
        SET created_at = CURRENT_TIMESTAMP
        WHERE created_at IS NULL
        """
    )


def ensure_column(conn, table_name, column_name, column_definition):
    columns = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    existing_columns = {column["name"] for column in columns}

    if column_name not in existing_columns:
        conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_definition}")


def seed_roles(conn):
    for role in ROLES:
        conn.execute(
            "INSERT OR IGNORE INTO roles(role_name) VALUES (?)",
            (role,),
        )


def seed_permissions(conn):
    for permission in PERMISSIONS:
        conn.execute(
            "INSERT OR IGNORE INTO permissions(permission_name) VALUES (?)",
            (permission,),
        )


def seed_role_permissions(conn):
    for role_name, permission_names in ROLE_PERMISSIONS.items():
        role = conn.execute(
            "SELECT id FROM roles WHERE role_name = ?",
            (role_name,),
        ).fetchone()

        if role is None:
            continue

        for permission_name in permission_names:
            permission = conn.execute(
                "SELECT id FROM permissions WHERE permission_name = ?",
                (permission_name,),
            ).fetchone()

            if permission is None:
                continue

            conn.execute(
                """
                INSERT OR IGNORE INTO role_permissions(role_id, permission_id)
                VALUES (?, ?)
                """,
                (role["id"], permission["id"]),
            )
