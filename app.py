import os

from flask import Flask, redirect, render_template, request, session, url_for

from admin import (
    create_user,
    get_all_roles,
    get_all_users,
    get_audit_logs,
    delete_user
)
from auth import authenticate_user, bcrypt, get_user_by_username, user_has_permission
from database import initialize_database, get_connection

def get_messages(username):
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT sender,message,timestamp
            FROM messages
            WHERE receiver=?
            ORDER BY timestamp DESC
            """,
            (username,)
        ).fetchall()


def send_message(sender, receiver, message):
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO messages(sender,receiver,message)
            VALUES(?,?,?)
            """,
            (sender, receiver, message)
        )
        conn.commit()


def create_app():
    app = Flask(__name__)

    app.config["SECRET_KEY"] = os.environ.get(
        "SECRET_KEY",
        "change-this-secret-key",
    )
    app.config["BCRYPT_LOG_ROUNDS"] = int(
        os.environ.get("BCRYPT_LOG_ROUNDS", "12")
    )

    bcrypt.init_app(app)

    with app.app_context():
        initialize_database()

    @app.route("/")
    def home():
        if "username" in session:
            return redirect(url_for("dashboard"))

        return render_template("home.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if "username" in session:
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            success, message = authenticate_user(username, password)

            if success:
                session["username"] = username
                return redirect(url_for("dashboard"))

            return render_template("login.html", error=message)

        return render_template("login.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if "username" in session:
            return redirect(url_for("dashboard"))

        error = None

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")

            if password != confirm_password:
                error = "Passwords do not match."
            else:
                employee_role = next(
                    (
                        role
                        for role in get_all_roles()
                        if role["role_name"] == "Employee"
                    ),
                    None,
                )

                if employee_role is None:
                    error = "Employee role is missing. Please initialize the database."
                else:
                    try:
                        created = create_user(
                            username,
                            password,
                            employee_role["id"],
                            created_by="self_registration",
                        )

                        if created:
                            session["username"] = username
                            return redirect(url_for("dashboard"))

                        error = f"User '{username}' already exists."
                    except ValueError as exc:
                        error = str(exc)

        return render_template("register.html", error=error)

    @app.route("/dashboard")
    def dashboard():
        if "username" not in session:
            return redirect(url_for("login"))

        user = get_user_by_username(session["username"])
        role = user["role_name"]

        image = None

        if role == "Employee":
            image = "employee.jpg"

        elif role == "Finance":
            image = "finance.jpg"

        return render_template(
            "dashboard.html",
            username=session["username"],
            role=role,
            image=image,
            messages=get_messages(session["username"])
        )

    @app.route("/messages", methods=["GET", "POST"])
    def messages():

        if "username" not in session:
            return redirect(url_for("login"))

        sender = session["username"]
        user = get_user_by_username(sender)
        role = user["role_name"]

        if request.method == "POST":

            text = request.form["message"]

            if role == "Employee":

                with get_connection() as conn:
                    hr = conn.execute(
                        """
                        SELECT username
                        FROM users
                        JOIN roles ON users.role_id = roles.id
                        WHERE role_name='HR'
                        LIMIT 1
                        """
                    ).fetchone()

                if hr is None:
                    return "No HR account found."

                receiver = hr["username"]

            else:
                receiver = request.form["receiver"]

                if not receiver:
                    return "Please select a recipient."

            send_message(sender, receiver, text)

        employees = []

        if role == "Admin":
            with get_connection() as conn:
                employees = conn.execute(
                    """
                    SELECT username
                    FROM users
                    WHERE username != ?
                    """,
                    (session["username"],)
                ).fetchall()

        elif role == "HR":
            with get_connection() as conn:
                employees = conn.execute(
                    """
                    SELECT username
                    FROM users
                    WHERE username != ?
                    """,
                    (session["username"],)
                ).fetchall()

        elif role == "Finance":
            with get_connection() as conn:
                employees = conn.execute(
                    """
                    SELECT username
                    FROM users
                    WHERE username != ?
                    """,
                    (session["username"],)
                ).fetchall()

        return render_template(
            "messages.html",
            role=role,
            employees=employees
        )

    @app.route("/users", methods=["GET", "POST"])
    def users():
        if "username" not in session:
            return redirect(url_for("login"))

        message = None
        error = None

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            role_id = request.form.get("role_id")

            try:
                created = create_user(
                    username,
                    password,
                    role_id,
                    created_by=session["username"],
                )

                if created:
                    message = f"User '{username}' created successfully."
                else:
                    error = f"User '{username}' already exists."
            except ValueError as exc:
                error = str(exc)

        return render_template(
            "users.html",
            users=get_all_users(),
            roles=get_all_roles(),
            message=message,
            error=error,
            current_role=get_user_by_username(session["username"])["role_name"]
        )

    @app.route("/delete-user/<int:user_id>")
    def delete_user_route(user_id):

        if "username" not in session:
            return redirect(url_for("login"))

        current_user = get_user_by_username(session["username"])
        current_role = current_user["role_name"]

        target = next(
            (u for u in get_all_users() if u["id"] == user_id),
            None
        )

        if target is None:
            return redirect(url_for("users"))

        # Prevent deleting yourself
        if target["username"] == session["username"]:
            return redirect(url_for("users"))

        # Admin can delete anyone except himself
        if current_role == "Admin":
            delete_user(
                user_id,
                deleted_by=session["username"]
            )

        # HR can only delete Employees
        elif current_role == "HR" and target["role_name"] == "Employee":
            delete_user(
                user_id,
                deleted_by=session["username"]
            )

        return redirect(url_for("users"))

    @app.route("/audit-logs")
    def audit_logs():
        if "username" not in session:
            return redirect(url_for("login"))

        return render_template("audit_logs.html", logs=get_audit_logs())
               
    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.errorhandler(404)
    def not_found(error):
        return render_template("error.html", message="Page not found."), 404

    @app.errorhandler(500)
    def internal_error(error):
        return render_template("error.html", message="Internal server error."), 500

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=os.environ.get("FLASK_DEBUG") == "1",
    )
