import os

import threading

import webbrowser

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

import os
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = "static/uploads"

ALLOWED_EXTENSIONS = {
    "png", "jpg", "jpeg", "gif",
    "pdf", "docx",
    "mp4", "mov", "avi"
}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return (
        "." in filename and
        filename.rsplit(".",1)[1].lower() in ALLOWED_EXTENSIONS
    )

def get_messages(user1, user2):
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT sender,receiver,message,media,timestamp
            FROM messages
            WHERE
                (sender=? AND receiver=?)
                OR
                (sender=? AND receiver=?)
            ORDER BY timestamp
            """,
            (user1, user2, user2, user1)
        ).fetchall()


def get_last_message(user1, user2):
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT message, media, timestamp
            FROM messages
            WHERE
                (sender=? AND receiver=?)
                OR
                (sender=? AND receiver=?)
            ORDER BY timestamp DESC
            LIMIT 1
            """,
            (user1, user2, user2, user1)
        ).fetchone()


def send_message(sender, receiver, message, media=None):
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO messages(sender,receiver,message,media)
            VALUES(?,?,?,?)
            """,
            (sender, receiver, message, media)
        )
        conn.commit()


def create_app():
    app = Flask(__name__)

    app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

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
            messages=[]        )
    @app.route("/profile")
    def profile():

        if "username" not in session:
            return redirect(url_for("login"))

        with get_connection() as conn:

            user = conn.execute(
                """
                SELECT *
                FROM users
                WHERE username=?
                """,
                (session["username"],)
            ).fetchone()

        return render_template(
            "profile.html",
            user=user
        )
    @app.route("/edit-profile", methods=["GET","POST"])
    def edit_profile():

        if "username" not in session:
            return redirect(url_for("login"))

        if request.method=="POST":

            bio=request.form["bio"]

            file=request.files.get("profile_pic")

            filename=None

            if file and file.filename!="":

                filename=secure_filename(file.filename)

                file.save(
                    os.path.join(
                        "static/uploads",
                        filename
                    )
                )

                with get_connection() as conn:

                    conn.execute(
                        """
                        UPDATE users
                        SET profile_pic=?, bio=?
                        WHERE username=?
                        """,
                        (
                            filename,
                            bio,
                            session["username"]
                        )
                    )

                    conn.commit()

            else:

                with get_connection() as conn:

                    conn.execute(
                        """
                        UPDATE users
                        SET bio=?
                        WHERE username=?
                        """,
                        (
                            bio,
                            session["username"]
                        )
                    )

                    conn.commit()

            return redirect(url_for("profile"))

        return render_template("edit_profile.html")
    @app.route("/messages", methods=["GET", "POST"])
    def messages():

        if "username" not in session:
            return redirect(url_for("login"))

        sender = session["username"]
        user = get_user_by_username(sender)
        role = user["role_name"]
        selected_user = request.args.get("user")

        if request.method == "POST":
            text = request.form["message"]
            file = request.files.get("file")

            filename = None

            if file and file.filename != "":
                if allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file.save(
                        os.path.join(
                            app.config["UPLOAD_FOLDER"],
                            filename
                        )
                    )
                else:
                    return "Invalid file type."

            receiver = selected_user

            if not receiver:
                return "Please select a recipient."

            send_message(sender, receiver, text, filename)

        with get_connection() as conn:

            users = conn.execute(
                """
                SELECT username, profile_pic
                FROM users
                WHERE username != ?
                """,
                (session["username"],)
            ).fetchall()

            contacts = []

            for user_row in users:
                username = user_row["username"]

                last_msg = get_last_message(
                    session["username"],
                    username
                )

                preview = "No messages yet"
                timestamp = ""

                if last_msg:
                    if last_msg["message"]:
                        preview = last_msg["message"]
                    elif last_msg["media"]:
                        preview = "📎 Attachment"
                    timestamp = last_msg["timestamp"]

                contacts.append({
                    "username": username,
                    "profile_pic": user_row["profile_pic"],
                    "preview": preview[:30],
                    "timestamp": timestamp
                })
            contacts.sort(
                key=lambda x: x["timestamp"] if x["timestamp"] else "",
                reverse=True
            )

            return render_template(
                "messages.html",
                role=role,
                messages=(
                    get_messages(session["username"], selected_user)
                    if selected_user
                    else []
                ),
                selected_user=selected_user,
                contacts=contacts,
                username=session["username"]
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
    @app.route("/messages_data/<user>")
    def messages_data(user):

        if "username" not in session:
            return []

        msgs = get_messages(session["username"], user)

        result = []

        for msg in msgs:
            result.append({
                "sender": msg["sender"],
                "message": msg["message"],
                "media": msg["media"],
                "timestamp": msg["timestamp"]
            })

        return result

    return app


app = create_app()


if __name__ == "__main__":

    threading.Timer(
        1.5,
        lambda: webbrowser.open("http://127.0.0.1:5000")
    ).start()

    app.run(
        host="127.0.0.1",
        port=5000
    )