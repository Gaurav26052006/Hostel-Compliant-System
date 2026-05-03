import os
import sqlite3
from datetime import datetime
from functools import wraps
from uuid import uuid4

import bcrypt
from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.utils import secure_filename


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "hostel_complaints.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret-key")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query_one(sql, params=()):
    return get_db().execute(sql, params).fetchone()


def query_all(sql, params=()):
    return get_db().execute(sql, params).fetchall()


def execute(sql, params=()):
    db = get_db()
    db.execute(sql, params)
    db.commit()


def hash_password(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def check_password(password, hashed):
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def current_user():
    if "user_id" not in session:
        return None
    return query_one("SELECT * FROM users WHERE id = ?", (session["user_id"],))


def login_required(role=None):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user:
                flash("Please login first.", "warning")
                return redirect(url_for("login"))
            if role and user["role"] != role:
                flash("You do not have access to that page.", "danger")
                return redirect(url_for("dashboard"))
            return view(*args, **kwargs)

        return wrapped

    return decorator


@app.context_processor
def inject_user():
    user = current_user()
    unread = 0
    if user:
        unread = query_one(
            "SELECT COUNT(*) AS count FROM notifications WHERE user_id = ? AND is_read = 0",
            (user["id"],),
        )["count"]
    return {"current_user": user, "unread_notifications": unread}


def notify(user_id, message):
    execute(
        "INSERT INTO notifications (user_id, message, created_at) VALUES (?, ?, ?)",
        (user_id, message, datetime.now().isoformat(timespec="seconds")),
    )


def add_timeline(complaint_id, status, note):
    execute(
        """
        INSERT INTO status_history (complaint_id, status, note, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (complaint_id, status, note, datetime.now().isoformat(timespec="seconds")),
    )


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            room TEXT,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('student', 'admin')),
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS complaints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            complaint_code TEXT UNIQUE NOT NULL,
            student_id INTEGER NOT NULL,
            room TEXT NOT NULL,
            category TEXT NOT NULL,
            priority TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            image_filename TEXT,
            status TEXT NOT NULL DEFAULT 'Pending',
            admin_note TEXT,
            rating INTEGER,
            rating_comment TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(student_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            complaint_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(complaint_id) REFERENCES complaints(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS status_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            complaint_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            note TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(complaint_id) REFERENCES complaints(id)
        );

        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """
    )
    admin = db.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1").fetchone()
    if not admin:
        db.execute(
            """
            INSERT INTO users (name, email, room, password_hash, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "Hostel Admin",
                "admin@hostel.com",
                None,
                hash_password("admin123"),
                "admin",
                datetime.now().isoformat(timespec="seconds"),
            ),
        )
    db.commit()


@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("home.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        room = request.form["room"].strip()
        password = request.form["password"]

        if query_one("SELECT id FROM users WHERE email = ?", (email,)):
            flash("Email already registered.", "danger")
            return redirect(url_for("signup"))

        execute(
            """
            INSERT INTO users (name, email, room, password_hash, role, created_at)
            VALUES (?, ?, ?, ?, 'student', ?)
            """,
            (name, email, room, hash_password(password), datetime.now().isoformat(timespec="seconds")),
        )
        flash("Signup complete. You can login now.", "success")
        return redirect(url_for("login"))
    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        requested_role = request.form["role"]
        user = query_one("SELECT * FROM users WHERE email = ?", (email,))

        if user and user["role"] == requested_role and check_password(password, user["password_hash"]):
            session["user_id"] = user["id"]
            flash(f"Welcome back, {user['name']}!", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid login details for the selected panel.", "danger")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("home"))


@app.route("/dashboard")
@login_required()
def dashboard():
    user = current_user()
    if user["role"] == "admin":
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("student_dashboard"))


@app.route("/student")
@login_required("student")
def student_dashboard():
    user = current_user()
    complaints = query_all(
        "SELECT * FROM complaints WHERE student_id = ? ORDER BY created_at DESC",
        (user["id"],),
    )
    stats = query_one(
        """
        SELECT
            COUNT(*) AS total,
            SUM(status = 'Pending') AS pending,
            SUM(status = 'In Progress') AS progress,
            SUM(status = 'Resolved') AS resolved
        FROM complaints WHERE student_id = ?
        """,
        (user["id"],),
    )
    return render_template("student_dashboard.html", complaints=complaints, stats=stats)


@app.route("/complaints/new", methods=["GET", "POST"])
@login_required("student")
def new_complaint():
    user = current_user()
    if request.method == "POST":
        file = request.files.get("image")
        filename = None
        if file and file.filename and allowed_file(file.filename):
            extension = secure_filename(file.filename).rsplit(".", 1)[1].lower()
            filename = f"{uuid4().hex}.{extension}"
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        now = datetime.now()
        complaint_code = f"HCS-{now.strftime('%Y%m%d')}-{uuid4().hex[:6].upper()}"
        execute(
            """
            INSERT INTO complaints
            (complaint_code, student_id, room, category, priority, title, description, image_filename, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                complaint_code,
                user["id"],
                request.form["room"].strip(),
                request.form["category"],
                request.form["priority"],
                request.form["title"].strip(),
                request.form["description"].strip(),
                filename,
                now.isoformat(timespec="seconds"),
                now.isoformat(timespec="seconds"),
            ),
        )
        complaint = query_one("SELECT id FROM complaints WHERE complaint_code = ?", (complaint_code,))
        add_timeline(complaint["id"], "Pending", "Complaint submitted by student.")
        notify(user["id"], f"Your complaint {complaint_code} was submitted successfully.")
        for admin in query_all("SELECT id FROM users WHERE role = 'admin'"):
            notify(admin["id"], f"New complaint {complaint_code} submitted from room {request.form['room']}.")
        flash(f"Complaint submitted with ID {complaint_code}.", "success")
        return redirect(url_for("complaint_detail", complaint_code=complaint_code))
    return render_template("new_complaint.html")


@app.route("/complaints/<complaint_code>", methods=["GET", "POST"])
@login_required()
def complaint_detail(complaint_code):
    user = current_user()
    complaint = query_one(
        """
        SELECT complaints.*, users.name AS student_name, users.email AS student_email
        FROM complaints
        JOIN users ON users.id = complaints.student_id
        WHERE complaint_code = ?
        """,
        (complaint_code,),
    )
    if not complaint:
        flash("Complaint not found.", "danger")
        return redirect(url_for("dashboard"))
    if user["role"] == "student" and complaint["student_id"] != user["id"]:
        flash("You can only view your own complaints.", "danger")
        return redirect(url_for("student_dashboard"))

    if request.method == "POST":
        action = request.form["action"]
        if action == "comment":
            message = request.form["message"].strip()
            if message:
                execute(
                    "INSERT INTO comments (complaint_id, user_id, message, created_at) VALUES (?, ?, ?, ?)",
                    (complaint["id"], user["id"], message, datetime.now().isoformat(timespec="seconds")),
                )
                recipient_id = complaint["student_id"] if user["role"] == "admin" else None
                if recipient_id:
                    notify(recipient_id, f"Admin commented on complaint {complaint_code}.")
                else:
                    for admin in query_all("SELECT id FROM users WHERE role = 'admin'"):
                        notify(admin["id"], f"Student replied on complaint {complaint_code}.")
                flash("Comment added.", "success")

        if action == "status" and user["role"] == "admin":
            status = request.form["status"]
            note = request.form["admin_note"].strip()
            execute(
                "UPDATE complaints SET status = ?, admin_note = ?, updated_at = ? WHERE id = ?",
                (status, note, datetime.now().isoformat(timespec="seconds"), complaint["id"]),
            )
            add_timeline(complaint["id"], status, note or f"Status changed to {status}.")
            notify(complaint["student_id"], f"Complaint {complaint_code} status updated to {status}.")
            flash("Complaint status updated.", "success")

        if action == "rating" and user["role"] == "student" and complaint["status"] == "Resolved":
            execute(
                "UPDATE complaints SET rating = ?, rating_comment = ?, updated_at = ? WHERE id = ?",
                (
                    int(request.form["rating"]),
                    request.form["rating_comment"].strip(),
                    datetime.now().isoformat(timespec="seconds"),
                    complaint["id"],
                ),
            )
            flash("Thanks for rating the service.", "success")

        return redirect(url_for("complaint_detail", complaint_code=complaint_code))

    comments = query_all(
        """
        SELECT comments.*, users.name, users.role
        FROM comments
        JOIN users ON users.id = comments.user_id
        WHERE complaint_id = ?
        ORDER BY comments.created_at ASC
        """,
        (complaint["id"],),
    )
    history = query_all(
        "SELECT * FROM status_history WHERE complaint_id = ? ORDER BY created_at ASC",
        (complaint["id"],),
    )
    return render_template("complaint_detail.html", complaint=complaint, comments=comments, history=history)


@app.route("/admin")
@login_required("admin")
def admin_dashboard():
    filters = {
        "q": request.args.get("q", "").strip(),
        "status": request.args.get("status", ""),
        "room": request.args.get("room", "").strip(),
        "category": request.args.get("category", ""),
        "date": request.args.get("date", ""),
    }
    where = []
    params = []
    if filters["q"]:
        where.append("(complaint_code LIKE ? OR title LIKE ?)")
        params.extend([f"%{filters['q']}%", f"%{filters['q']}%"])
    if filters["status"]:
        where.append("status = ?")
        params.append(filters["status"])
    if filters["room"]:
        where.append("room LIKE ?")
        params.append(f"%{filters['room']}%")
    if filters["category"]:
        where.append("category = ?")
        params.append(filters["category"])
    if filters["date"]:
        where.append("DATE(created_at) = ?")
        params.append(filters["date"])
    where_sql = "WHERE " + " AND ".join(where) if where else ""

    complaints = query_all(
        f"""
        SELECT complaints.*, users.name AS student_name
        FROM complaints
        JOIN users ON users.id = complaints.student_id
        {where_sql}
        ORDER BY complaints.created_at DESC
        """,
        params,
    )
    stats = query_one(
        """
        SELECT
            COUNT(*) AS total,
            SUM(status = 'Pending') AS pending,
            SUM(status = 'In Progress') AS progress,
            SUM(status = 'Resolved') AS resolved
        FROM complaints
        """
    )
    return render_template("admin_dashboard.html", complaints=complaints, stats=stats, filters=filters)


@app.route("/notifications")
@login_required()
def notifications():
    user = current_user()
    notes = query_all(
        "SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC",
        (user["id"],),
    )
    execute("UPDATE notifications SET is_read = 1 WHERE user_id = ?", (user["id"],))
    return render_template("notifications.html", notifications=notes)


@app.route("/uploads/<filename>")
@login_required()
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(debug=True)
