import os

from flask import Flask

from auth import bcrypt, register_user
from database import initialize_database


DEFAULT_ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
DEFAULT_ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "Admin@123")
DEFAULT_ADMIN_ROLE_ID = int(os.environ.get("ADMIN_ROLE_ID", "1"))


def create_seed_app():
    app = Flask(__name__)
    app.config["BCRYPT_LOG_ROUNDS"] = int(os.environ.get("BCRYPT_LOG_ROUNDS", "12"))
    bcrypt.init_app(app)
    return app


def main():
    app = create_seed_app()

    with app.app_context():
        initialize_database()
        created = register_user(
            DEFAULT_ADMIN_USERNAME,
            DEFAULT_ADMIN_PASSWORD,
            DEFAULT_ADMIN_ROLE_ID,
        )

    if created:
        print(f"User '{DEFAULT_ADMIN_USERNAME}' created successfully.")
    else:
        print(f"User '{DEFAULT_ADMIN_USERNAME}' already exists or could not be created.")


if __name__ == "__main__":
    main()
