from flask_bcrypt import Bcrypt
from database import get_connection

bcrypt = Bcrypt()

def register_user(username, password, role_id):
    conn = get_connection()
    cursor = conn.cursor()

    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    cursor.execute(
        """
        INSERT INTO users(username, password_hash, role_id)
        VALUES (?, ?, ?)
        """,
        (username, password_hash, role_id)
    )

    conn.commit()
    conn.close()