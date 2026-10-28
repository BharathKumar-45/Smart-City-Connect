import smtplib
from email.message import EmailMessage
import os
import sqlite3
import secrets
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session, g, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


app = Flask(__name__)

# For a local college demo only.
app.secret_key = os.environ.get(
    "SECRET_KEY", "local-demo-key-change-before-deployment"
)

UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}
MAX_PHOTO_SIZE = 5 * 1024 * 1024  # 5 MB

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["MAX_CONTENT_LENGTH"] = MAX_PHOTO_SIZE + (1024 * 1024)

DATABASE = os.path.join(app.root_path, "complaints.db")

CATEGORIES = [
    "Pothole",
    "Garbage Overflow",
    "Water Leakage",
    "Broken Streetlight",
    "Drainage Problem",
    "Other"
]

PRIORITIES = ["Low", "Medium", "High"]
STATUSES = ["Submitted", "In Progress", "Resolved", "Rejected"]


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    connection = sqlite3.connect(DATABASE)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS complaints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            complaint_id TEXT UNIQUE,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            location TEXT NOT NULL,
            photo TEXT,
            latitude REAL,
            longitude REAL,
            priority TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Submitted',
            department TEXT DEFAULT 'Not Assigned',
            admin_remark TEXT DEFAULT '',
            created_at TEXT NOT NULL DEFAULT
                (datetime('now', 'localtime'))
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    existing_columns = {
        row[1] for row in connection.execute(
            "PRAGMA table_info(complaints)"
        ).fetchall()
    }

    for column, definition in [
        ("photo", "TEXT"),
        ("latitude", "REAL"),
        ("longitude", "REAL"),
        ("user_id", "INTEGER")
    ]:
        if column not in existing_columns:
            connection.execute(
                f"ALTER TABLE complaints ADD COLUMN {column} {definition}"
            )

    connection.commit()
    connection.close()


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def admin_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get("admin_logged_in"):
            flash("Please log in as admin first.", "error")
            return redirect(url_for("admin"))
        return view(*args, **kwargs)
    return wrapped_view


def citizen_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to submit a report.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped_view


def send_resolution_email(to_email, citizen_name, complaint_id,
                          complaint_title, admin_remark):
    """Send an email when a citizen's complaint is resolved."""

    smtp_server = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_email = os.environ.get("SMTP_EMAIL")
    smtp_password = os.environ.get("SMTP_PASSWORD")

    # Do not attempt to send if email settings are missing.
    if not smtp_email or not smtp_password:
        app.logger.warning(
            "Resolution email not sent: SMTP settings are missing."
        )
        return False

    message = EmailMessage()
    message["Subject"] = f"Your complaint {complaint_id} is resolved"
    message["From"] = smtp_email
    message["To"] = to_email

    message.set_content(f"""Hello {citizen_name},

Good news! Your city complaint has been marked as RESOLVED.

Complaint ID: {complaint_id}
Issue: {complaint_title}
Status: Resolved

Admin remark: {admin_remark or "No additional remark was provided."}

Thank you for helping us improve our city.

SmartCity Connect Team
""")

    try:
        with smtplib.SMTP(smtp_server, smtp_port, timeout=20) as server:
            server.starttls()
            server.login(smtp_email, smtp_password)
            server.send_message(message)

        app.logger.info(
            "Resolution email sent for complaint %s", complaint_id
        )
        return True

    except (smtplib.SMTPException, OSError):
        app.logger.exception(
            "Failed to send resolution email for complaint %s",
            complaint_id
        )
        return False


@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("report"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or len(name) > 100:
            flash("Enter a valid name.", "error")
        elif (
            not email
            or len(email) > 254
            or "@" not in email
            or "." not in email.rsplit("@", 1)[-1]
        ):
            flash("Enter a valid email address.", "error")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
        else:
            db = get_db()
            try:
                db.execute("""
                    INSERT INTO users (name, email, password_hash)
                    VALUES (?, ?, ?)
                """, (
                    name,
                    email,
                    generate_password_hash(password)
                ))
                db.commit()
                flash("Account created! Please log in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                db.rollback()
                flash("That email is already registered.", "error")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("report"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = get_db().execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            return redirect(url_for("report"))

        flash("Incorrect email or password.", "error")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.pop("user_id", None)
    session.pop("user_name", None)
    flash("You have logged out.", "success")
    return redirect(url_for("login"))


@app.route("/")
def index():
    db = get_db()

    total = db.execute(
        "SELECT COUNT(*) FROM complaints"
    ).fetchone()[0]

    pending = db.execute(
        "SELECT COUNT(*) FROM complaints WHERE status = ?",
        ("Submitted",)
    ).fetchone()[0]

    in_progress = db.execute(
        "SELECT COUNT(*) FROM complaints WHERE status = ?",
        ("In Progress",)
    ).fetchone()[0]

    resolved = db.execute(
        "SELECT COUNT(*) FROM complaints WHERE status = ?",
        ("Resolved",)
    ).fetchone()[0]

    return render_template(
        "index.html",
        total=total,
        pending=pending,
        in_progress=in_progress,
        resolved=resolved
    )


@app.route("/report", methods=["GET", "POST"])
@citizen_required
def report():
    if request.method == "POST":
        category = request.form.get("category", "").strip()
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        location = request.form.get("location", "").strip()
        priority = request.form.get("priority", "").strip()

        latitude_text = request.form.get("latitude", "").strip()
        longitude_text = request.form.get("longitude", "").strip()
        photo = request.files.get("photo")

        latitude = None
        longitude = None

        try:
            if latitude_text or longitude_text:
                latitude = float(latitude_text)
                longitude = float(longitude_text)

                if (
                    not (-90 <= latitude <= 90)
                    or not (-180 <= longitude <= 180)
                ):
                    raise ValueError
        except (ValueError, TypeError):
            flash("Please select a valid map location.", "error")
            return redirect(url_for("report"))

        if (
            category not in CATEGORIES
            or priority not in PRIORITIES
            or not title
            or not description
            or not location
            or len(title) > 120
            or len(description) > 2000
            or len(location) > 200
        ):
            flash(
                "Please enter valid information in every required field.",
                "error"
            )
            return redirect(url_for("report"))

        photo_filename = None

        if photo and photo.filename:
            if not allowed_file(photo.filename):
                flash("Use a JPG, JPEG, PNG or WEBP photo.", "error")
                return redirect(url_for("report"))

            photo_data = photo.read(MAX_PHOTO_SIZE + 1)

            if len(photo_data) > MAX_PHOTO_SIZE:
                flash("The photo must be 5 MB or smaller.", "error")
                return redirect(url_for("report"))

            extension = secure_filename(
                photo.filename.rsplit(".", 1)[1].lower()
            )
            photo_filename = f"{secrets.token_hex(16)}.{extension}"

            photo_path = os.path.join(UPLOAD_FOLDER, photo_filename)
            with open(photo_path, "wb") as saved_photo:
                saved_photo.write(photo_data)

        db = get_db()

        try:
            cursor = db.execute("""
                INSERT INTO complaints
                    (user_id, category, title, description, location,
                     priority, photo, latitude, longitude)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session["user_id"],
                category,
                title,
                description,
                location,
                priority,
                photo_filename,
                latitude,
                longitude
            ))

            row_id = cursor.lastrowid
            complaint_id = f"SC-{1000 + row_id}"

            db.execute(
                "UPDATE complaints SET complaint_id = ? WHERE id = ?",
                (complaint_id, row_id)
            )
            db.commit()

        except Exception:
            db.rollback()

            if photo_filename:
                photo_path = os.path.join(UPLOAD_FOLDER, photo_filename)
                if os.path.exists(photo_path):
                    os.remove(photo_path)

            app.logger.exception("Could not save complaint")
            flash("Could not save your complaint. Please try again.", "error")
            return redirect(url_for("report"))

        return render_template(
            "report.html",
            categories=CATEGORIES,
            priorities=PRIORITIES,
            submitted_id=complaint_id
        )

    return render_template(
        "report.html",
        categories=CATEGORIES,
        priorities=PRIORITIES
    )


@app.route("/track", methods=["GET", "POST"])
def track():
    complaint = None
    searched = False

    if request.method == "POST":
        searched = True
        complaint_id = request.form.get(
            "complaint_id", ""
        ).strip().upper()

        complaint = get_db().execute(
            "SELECT * FROM complaints WHERE complaint_id = ?",
            (complaint_id,)
        ).fetchone()

    return render_template(
        "track.html",
        complaint=complaint,
        searched=searched,
        statuses=STATUSES
    )


@app.route("/admin", methods=["GET", "POST"])
def admin():
    if session.get("admin_logged_in"):
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        expected_username = os.environ.get("ADMIN_USERNAME", "Phoenix")
        expected_password = os.environ.get("ADMIN_PASSWORD", "Phoenix.171")

        if (
            username == expected_username
            and password == expected_password
        ):
            session.clear()
            session["admin_logged_in"] = True
            return redirect(url_for("admin_dashboard"))

        flash("Incorrect username or password.", "error")

    return render_template("admin.html", logged_in=False)


@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    db = get_db()
    search = request.args.get("q", "").strip()
    if search:
        pattern = f"%{search}%"
        complaints = db.execute("""
            SELECT * FROM complaints
            WHERE complaint_id LIKE ?
               OR title LIKE ?
               OR location LIKE ?
            ORDER BY id DESC
        """, (pattern, pattern, pattern)).fetchall()
    else:
        complaints = db.execute("""
            SELECT * FROM complaints
            ORDER BY id DESC
        """).fetchall()

    total = db.execute(
        "SELECT COUNT(*) FROM complaints"
    ).fetchone()[0]

    pending = db.execute(
        "SELECT COUNT(*) FROM complaints WHERE status = ?",
        ("Submitted",)
    ).fetchone()[0]

    in_progress = db.execute(
        "SELECT COUNT(*) FROM complaints WHERE status = ?",
        ("In Progress",)
    ).fetchone()[0]

    resolved = db.execute(
        "SELECT COUNT(*) FROM complaints WHERE status = ?",
        ("Resolved",)
    ).fetchone()[0]

    return render_template(
        "admin.html",
        logged_in=True,
        complaints=complaints,
        statuses=STATUSES,
        total=total,
        pending=pending,
        in_progress=in_progress,
        resolved=resolved,
        search=search
    )


@app.route("/admin/update/<int:row_id>", methods=["POST"])
@admin_required
def update_complaint(row_id):
    status = request.form.get("status", "")
    department = request.form.get("department", "").strip()
    remark = request.form.get("admin_remark", "").strip()

    if (
        status not in STATUSES
        or len(department) > 100
        or len(remark) > 1000
    ):
        flash("Invalid update. Please check the fields.", "error")
        return redirect(url_for("admin_dashboard"))

    db = get_db()

    # Get the old status and the citizen's registered email.
    complaint = db.execute("""
        SELECT
            c.id,
            c.complaint_id,
            c.title,
            c.status,
            u.name AS citizen_name,
            u.email AS citizen_email
        FROM complaints AS c
        LEFT JOIN users AS u ON u.id = c.user_id
        WHERE c.id = ?
    """, (row_id,)).fetchone()

    if complaint is None:
        flash("Complaint not found.", "error")
        return redirect(url_for("admin_dashboard"))

    # Send an email only for a new transition to Resolved.
    should_notify = (
        status == "Resolved"
        and complaint["status"] != "Resolved"
    )

    try:
        db.execute("""
            UPDATE complaints
            SET status = ?, department = ?, admin_remark = ?
            WHERE id = ?
        """, (
            status,
            department or "Not Assigned",
            remark,
            row_id
        ))
        db.commit()

    except sqlite3.Error:
        db.rollback()
        app.logger.exception("Could not update complaint %s", row_id)
        flash("Could not update the complaint. Please try again.", "error")
        return redirect(url_for("admin_dashboard"))

    if should_notify:
        email = complaint["citizen_email"]

        if email:
            email_sent = send_resolution_email(
                to_email=email,
                citizen_name=complaint["citizen_name"] or "Citizen",
                complaint_id=complaint["complaint_id"],
                complaint_title=complaint["title"],
                admin_remark=remark
            )

            if email_sent:
                flash(
                    "Complaint resolved and notification email sent.",
                    "success"
                )
            else:
                flash(
                    "Complaint resolved, but the email could not be sent. "
                    "Check your email configuration and application logs.",
                    "error"
                )
        else:
            flash(
                "Complaint resolved, but no registered citizen email "
                "was found for this complaint.",
                "error"
            )
    else:
        flash("Complaint updated successfully.", "success")

    return redirect(url_for("admin_dashboard"))



@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.clear()
    flash("You have logged out.", "success")
    return redirect(url_for("admin"))


@app.route("/about")
def about():
    return render_template("about.html")


# Free SmartCity chatbot using predefined responses.
# No Gemini API key or external AI service is required.
@app.route("/api/chat", methods=["POST"])
def ai_chat():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "")

    if not isinstance(message, str) or not message.strip():
        return jsonify({"reply": "Please enter a question."}), 400

    if len(message) > 1000:
        return jsonify({
            "reply": "Please keep your question under 1000 characters."
        }), 400

    text = message.strip().lower()

    if any(word in text for word in [
        "hello", "hi", "hey", "good morning", "good evening"
    ]):
        reply = (
            "Hello! Welcome to SmartCity Connect. "
            "I can help you report city problems and track complaints."
        )

    elif any(word in text for word in [
        "pothole", "road damage", "damaged road"
    ]):
        reply = (
            "To report a pothole, log in and open the Report page. "
            "Select Pothole, enter the location and description, "
            "and submit your report."
        )

    elif any(word in text for word in [
        "garbage", "trash", "waste", "rubbish"
    ]):
        reply = (
            "To report garbage overflow, log in and open the Report "
            "page. Select Garbage Overflow, enter the location "
            "and details, and submit your report."
        )

    elif any(word in text for word in [
        "water leak", "water leakage", "leaking pipe"
    ]):
        reply = (
            "To report water leakage, open the Report page, "
            "select Water Leakage, and enter the location and details."
        )

    elif any(word in text for word in [
        "streetlight", "street light", "street lamp"
    ]):
        reply = (
            "To report a broken streetlight, open the Report page, "
            "select Broken Streetlight, and enter the details."
        )

    elif any(word in text for word in [
        "drainage", "blocked drain", "drain problem"
    ]):
        reply = (
            "To report a drainage problem, open the Report page, "
            "select Drainage Problem, and provide the location and details."
        )

    elif any(word in text for word in [
        "report", "submit", "complaint", "register issue"
    ]):
        reply = (
            "Log in, open the Report page, complete the required fields, "
            "and submit your complaint. Keep the complaint ID for tracking."
        )
    elif "not resolved" in text or "no action" in text:
        reply = (
            "Check your complaint status using your complaint ID. "
            "If it remains unresolved, contact the responsible "
            "department or administrator."
        )

    elif "in progress" in text:
        reply = (
            "In Progress means your complaint is being worked on "
            "and has not yet been marked as resolved."
        )

    elif "resolved" in text:
        reply = (
            "Resolved means the administrator has marked the "
            "complaint as addressed. Check the Track page for its status."
        )

    elif any(word in text for word in [
        "track", "tracking", "status", "complaint id"
    ]):
        reply = (
            "Open the Track page and enter your complaint ID "
            "to check the current status."
        )

    elif any(word in text for word in [
        "login", "log in", "sign in", "account"
    ]):
        reply = (
            "Use the Login page to access your account. "
            "If you are new, create an account on the Register page."
        )

    elif any(word in text for word in [
        "photo", "image", "picture"
    ]):
        reply = (
            "You can attach a JPG, JPEG, PNG, or WEBP photo "
            "to a report. The maximum photo size is 5 MB."
        )

    elif any(word in text for word in [
        "help", "features", "what can you do"
    ]):
        reply = (
            "I can explain how to report potholes, garbage overflow, "
            "water leakage, broken streetlights, and drainage problems. "
            "I can also help you understand complaint tracking."
        )

    elif "thank" in text:
        reply = "You're welcome! I'm here to help you use SmartCity Connect."

    elif "smart city" in text or "smart cities" in text:
        reply = (
            "A Smart City uses technology and data to improve "
            "transportation, water supply, waste management, "
            "street lighting, and public safety. SmartCity Connect "
            "helps citizens report and track city problems online."
        )

    
    else:
        reply = (
            "I don't have an answer for that question yet. "
            "Try asking how to report a pothole, report garbage, "
            "submit a complaint, or track a complaint."
        )

    return jsonify({"reply": reply})


init_db()

if __name__ == "__main__":
    app.run(debug=True)
