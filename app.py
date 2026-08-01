import os
import sqlite3
import time
import uuid
from functools import wraps

from flask import (
    Flask, g, render_template, request, redirect,
    url_for, session, flash, send_from_directory, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "adda.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
ALLOWED_EXT = {"png", "jpg", "jpeg", "gif", "webp"}
STORY_LIFETIME_SECONDS = 24 * 60 * 60

app = Flask(__name__)
# IMPORTANT: change this secret key before putting the site online for real.
app.config["SECRET_KEY"] = os.environ.get("ADDA_SECRET_KEY", "dev-secret-change-me")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 6 * 1024 * 1024  # 6 MB uploads max

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ---------------------------------------------------------------- database
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            identifier TEXT NOT NULL UNIQUE,
            id_type TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            avatar TEXT,
            bio TEXT DEFAULT '',
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            text TEXT DEFAULT '',
            image TEXT,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS likes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(post_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            text TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS stories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            text TEXT DEFAULT '',
            image TEXT,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS friendships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            friend_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(user_id, friend_id)
        );

        CREATE TABLE IF NOT EXISTS friend_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at INTEGER NOT NULL,
            UNIQUE(sender_id, receiver_id)
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            text TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        """
    )
    db.commit()
    db.close()


# ---------------------------------------------------------------- helpers
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT


def save_upload(file_storage):
    """Save an uploaded image, return the stored filename or None."""
    if not file_storage or file_storage.filename == "":
        return None
    if not allowed_file(file_storage.filename):
        return None
    ext = file_storage.filename.rsplit(".", 1)[1].lower()
    fname = f"{uuid.uuid4().hex}.{ext}"
    file_storage.save(os.path.join(app.config["UPLOAD_FOLDER"], fname))
    return fname


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def friend_ids_of(db, user_id):
    rows = db.execute("SELECT friend_id FROM friendships WHERE user_id = ?", (user_id,)).fetchall()
    return {r["friend_id"] for r in rows}


def sent_request_ids_of(db, user_id):
    """IDs of people this user has sent a pending friend request to."""
    rows = db.execute("SELECT receiver_id FROM friend_requests WHERE sender_id = ?", (user_id,)).fetchall()
    return {r["receiver_id"] for r in rows}


def time_ago(ts):
    diff = int(time.time()) - int(ts)
    if diff < 60:
        return "এইমাত্র"
    if diff < 3600:
        return f"{diff // 60} মিনিট আগে"
    if diff < 86400:
        return f"{diff // 3600} ঘন্টা আগে"
    if diff < 7 * 86400:
        return f"{diff // 86400} দিন আগে"
    return time.strftime("%d %b %Y", time.localtime(ts))


app.jinja_env.filters["time_ago"] = time_ago


@app.context_processor
def inject_user():
    return {"me": current_user()}


# ---------------------------------------------------------------- auth
@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("home"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        id_type = request.form.get("id_type", "phone")
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")

        if not name or not identifier or not password:
            flash("সব ঘর পূরণ করুন।", "error")
            return render_template("register.html")

        db = get_db()
        exists = db.execute(
            "SELECT id FROM users WHERE identifier = ?", (identifier.lower(),)
        ).fetchone()
        if exists:
            msg = "এই নাম্বার দিয়ে আগেই একটা একাউন্ট আছে।" if id_type == "phone" \
                else "এই জিমেইল দিয়ে আগেই একটা একাউন্ট আছে।"
            flash(msg, "error")
            return render_template("register.html")

        pw_hash = generate_password_hash(password)
        db.execute(
            "INSERT INTO users (name, identifier, id_type, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
            (name, identifier.lower(), id_type, pw_hash, int(time.time())),
        )
        db.commit()
        user = db.execute("SELECT id FROM users WHERE identifier = ?", (identifier.lower(),)).fetchone()
        session["user_id"] = user["id"]
        flash(f"স্বাগতম, {name}!", "success")
        return redirect(url_for("home"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("home"))

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip().lower()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE identifier = ?", (identifier,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            return redirect(url_for("home"))
        flash("নাম্বার/জিমেইল অথবা পাসওয়ার্ড ভুল।", "error")
        return render_template("login.html")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------- home / feed
@app.route("/")
@login_required
def home():
    db = get_db()
    me = current_user()
    friends = friend_ids_of(db, me["id"])
    sent_ids = sent_request_ids_of(db, me["id"])

    cutoff = int(time.time()) - STORY_LIFETIME_SECONDS
    story_authors = db.execute(
        """SELECT DISTINCT u.id, u.name, u.avatar
           FROM stories s JOIN users u ON u.id = s.user_id
           WHERE s.created_at > ?
           ORDER BY (u.id = ?) DESC, s.created_at DESC""",
        (cutoff, me["id"]),
    ).fetchall()

    posts = db.execute(
        """SELECT p.*, u.name AS author_name, u.avatar AS author_avatar
           FROM posts p JOIN users u ON u.id = p.user_id
           ORDER BY p.created_at DESC"""
    ).fetchall()

    def sort_key(p):
        is_close = (p["user_id"] == me["id"]) or (p["user_id"] in friends)
        return (0 if is_close else 1, -p["created_at"])

    posts = sorted(posts, key=sort_key)

    enriched = []
    for p in posts:
        likes = db.execute("SELECT user_id FROM likes WHERE post_id = ?", (p["id"],)).fetchall()
        like_ids = {r["user_id"] for r in likes}
        comments = db.execute(
            """SELECT c.*, u.name AS author_name FROM comments c
               JOIN users u ON u.id = c.user_id
               WHERE c.post_id = ? ORDER BY c.created_at ASC""",
            (p["id"],),
        ).fetchall()
        enriched.append({
            "row": p,
            "like_count": len(like_ids),
            "liked_by_me": me["id"] in like_ids,
            "comments": comments,
            "is_friend": p["user_id"] in friends,
            "is_me": p["user_id"] == me["id"],
            "is_requested": p["user_id"] in sent_ids,
        })

    return render_template("home.html", posts=enriched, story_authors=story_authors)


@app.route("/post/new", methods=["POST"])
@login_required
def new_post():
    me = current_user()
    text = request.form.get("text", "").strip()
    image_file = request.files.get("image")
    image_name = save_upload(image_file)

    if not text and not image_name:
        flash("পোস্টে কিছু একটা লেখো বা ছবি দাও।", "error")
        return redirect(url_for("home"))

    db = get_db()
    db.execute(
        "INSERT INTO posts (user_id, text, image, created_at) VALUES (?, ?, ?, ?)",
        (me["id"], text, image_name, int(time.time())),
    )
    db.commit()
    return redirect(url_for("home"))


@app.route("/post/<int:post_id>/like", methods=["POST"])
@login_required
def like_post(post_id):
    me = current_user()
    db = get_db()
    row = db.execute("SELECT id FROM likes WHERE post_id = ? AND user_id = ?", (post_id, me["id"])).fetchone()
    if row:
        db.execute("DELETE FROM likes WHERE id = ?", (row["id"],))
    else:
        db.execute("INSERT INTO likes (post_id, user_id) VALUES (?, ?)", (post_id, me["id"]))
    db.commit()
    return redirect(request.referrer or url_for("home"))


@app.route("/post/<int:post_id>/comment", methods=["POST"])
@login_required
def comment_post(post_id):
    text = request.form.get("text", "").strip()
    if text:
        db = get_db()
        db.execute(
            "INSERT INTO comments (post_id, user_id, text, created_at) VALUES (?, ?, ?, ?)",
            (post_id, current_user()["id"], text, int(time.time())),
        )
        db.commit()
    return redirect(request.referrer or url_for("home"))


# ---------------------------------------------------------------- stories
@app.route("/story/new", methods=["GET", "POST"])
@login_required
def new_story():
    if request.method == "POST":
        text = request.form.get("text", "").strip()
        image_file = request.files.get("image")
        image_name = save_upload(image_file)
        if not text and not image_name:
            flash("স্টোরিতে কিছু একটা লেখো বা ছবি দাও।", "error")
            return redirect(url_for("new_story"))
        db = get_db()
        db.execute(
            "INSERT INTO stories (user_id, text, image, created_at) VALUES (?, ?, ?, ?)",
            (current_user()["id"], text, image_name, int(time.time())),
        )
        db.commit()
        return redirect(url_for("home"))
    return render_template("story_new.html")


@app.route("/story/user/<int:user_id>")
@login_required
def view_stories(user_id):
    db = get_db()
    cutoff = int(time.time()) - STORY_LIFETIME_SECONDS
    stories = db.execute(
        "SELECT * FROM stories WHERE user_id = ? AND created_at > ? ORDER BY created_at ASC",
        (user_id, cutoff),
    ).fetchall()
    author = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not stories or not author:
        return redirect(url_for("home"))
    return render_template("story_view.html", stories=stories, author=author)


# ---------------------------------------------------------------- people & friends
@app.route("/people")
@login_required
def people():
    db = get_db()
    me = current_user()
    tab = request.args.get("tab", "all")
    if tab not in ("all", "requests", "friends"):
        tab = "all"

    friend_ids = friend_ids_of(db, me["id"])
    sent_ids = sent_request_ids_of(db, me["id"])

    all_users = db.execute(
        "SELECT * FROM users WHERE id != ? ORDER BY name ASC", (me["id"],)
    ).fetchall()

    incoming_requests = db.execute(
        """SELECT u.id, u.name, u.avatar, fr.created_at
           FROM friend_requests fr JOIN users u ON u.id = fr.sender_id
           WHERE fr.receiver_id = ?
           ORDER BY fr.created_at DESC""",
        (me["id"],),
    ).fetchall()

    my_friends = db.execute(
        """SELECT u.* FROM users u
           JOIN friendships f ON f.friend_id = u.id
           WHERE f.user_id = ?
           ORDER BY u.name ASC""",
        (me["id"],),
    ).fetchall()

    return render_template(
        "people.html",
        tab=tab,
        all_users=all_users,
        incoming_requests=incoming_requests,
        my_friends=my_friends,
        friend_ids=friend_ids,
        sent_ids=sent_ids,
        request_count=len(incoming_requests),
    )


@app.route("/friend-request/<int:user_id>", methods=["POST"])
@login_required
def send_friend_request(user_id):
    me = current_user()
    db = get_db()
    if user_id == me["id"]:
        return redirect(request.referrer or url_for("people"))

    already_friends = db.execute(
        "SELECT 1 FROM friendships WHERE user_id = ? AND friend_id = ?", (me["id"], user_id)
    ).fetchone()
    if already_friends:
        return redirect(request.referrer or url_for("people"))

    # if they already sent ME a request, accept it instead of creating a duplicate
    their_request = db.execute(
        "SELECT id FROM friend_requests WHERE sender_id = ? AND receiver_id = ?", (user_id, me["id"])
    ).fetchone()
    if their_request:
        return _accept_request(db, me["id"], user_id)

    db.execute(
        "INSERT OR IGNORE INTO friend_requests (sender_id, receiver_id, created_at) VALUES (?, ?, ?)",
        (me["id"], user_id, int(time.time())),
    )
    db.commit()
    flash("ফ্রেন্ড রিকোয়েস্ট পাঠানো হয়েছে!", "success")
    return redirect(request.referrer or url_for("people"))


def _accept_request(db, me_id, other_id):
    db.execute("DELETE FROM friend_requests WHERE sender_id = ? AND receiver_id = ?", (other_id, me_id))
    db.execute("INSERT OR IGNORE INTO friendships (user_id, friend_id) VALUES (?, ?)", (me_id, other_id))
    db.execute("INSERT OR IGNORE INTO friendships (user_id, friend_id) VALUES (?, ?)", (other_id, me_id))
    db.commit()
    flash("এখন থেকে তোমরা বন্ধু!", "success")
    return redirect(request.referrer or url_for("people", tab="friends"))


@app.route("/friend-request/<int:user_id>/accept", methods=["POST"])
@login_required
def accept_friend_request(user_id):
    me = current_user()
    db = get_db()
    return _accept_request(db, me["id"], user_id)


@app.route("/friend-request/<int:user_id>/decline", methods=["POST"])
@login_required
def decline_friend_request(user_id):
    me = current_user()
    db = get_db()
    db.execute(
        "DELETE FROM friend_requests WHERE sender_id = ? AND receiver_id = ?", (user_id, me["id"])
    )
    db.commit()
    return redirect(request.referrer or url_for("people", tab="requests"))


# ---------------------------------------------------------------- profile
@app.route("/profile/<int:user_id>")
@login_required
def profile(user_id):
    db = get_db()
    me = current_user()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        abort(404)
    posts = db.execute(
        "SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC", (user_id,)
    ).fetchall()
    enriched = []
    for p in posts:
        like_count = db.execute("SELECT COUNT(*) c FROM likes WHERE post_id = ?", (p["id"],)).fetchone()["c"]
        liked_by_me = db.execute(
            "SELECT 1 FROM likes WHERE post_id = ? AND user_id = ?", (p["id"], me["id"])
        ).fetchone() is not None
        comments = db.execute(
            """SELECT c.*, u.name AS author_name FROM comments c
               JOIN users u ON u.id = c.user_id WHERE c.post_id = ? ORDER BY c.created_at ASC""",
            (p["id"],),
        ).fetchall()
        enriched.append({"row": p, "like_count": like_count, "liked_by_me": liked_by_me, "comments": comments})

    friend_count = db.execute("SELECT COUNT(*) c FROM friendships WHERE user_id = ?", (user_id,)).fetchone()["c"]
    is_friend = user_id in friend_ids_of(db, me["id"])
    is_requested = user_id in sent_request_ids_of(db, me["id"])
    return render_template(
        "profile.html", profile_user=user, posts=enriched,
        friend_count=friend_count, is_friend=is_friend, is_requested=is_requested,
        is_me=(user_id == me["id"])
    )


@app.route("/profile/update", methods=["POST"])
@login_required
def update_profile():
    me = current_user()
    bio = request.form.get("bio", "").strip()
    avatar_file = request.files.get("avatar")
    avatar_name = save_upload(avatar_file)
    db = get_db()
    if avatar_name:
        db.execute("UPDATE users SET bio = ?, avatar = ? WHERE id = ?", (bio, avatar_name, me["id"]))
    else:
        db.execute("UPDATE users SET bio = ? WHERE id = ?", (bio, me["id"]))
    db.commit()
    return redirect(url_for("profile", user_id=me["id"]))


# ---------------------------------------------------------------- messages
@app.route("/messages")
@login_required
def messages_inbox():
    db = get_db()
    me = current_user()
    rows = db.execute(
        """SELECT u.id, u.name, u.avatar,
                  (SELECT text FROM messages
                    WHERE (sender_id = u.id AND receiver_id = ?) OR (sender_id = ? AND receiver_id = u.id)
                    ORDER BY created_at DESC LIMIT 1) AS last_text,
                  (SELECT MAX(created_at) FROM messages
                    WHERE (sender_id = u.id AND receiver_id = ?) OR (sender_id = ? AND receiver_id = u.id)) AS last_at
           FROM users u
           WHERE u.id != ?
             AND EXISTS (
                SELECT 1 FROM messages
                WHERE (sender_id = u.id AND receiver_id = ?) OR (sender_id = ? AND receiver_id = u.id)
             )
           ORDER BY last_at DESC""",
        (me["id"], me["id"], me["id"], me["id"], me["id"], me["id"], me["id"]),
    ).fetchall()
    return render_template("messages.html", conversations=rows)


@app.route("/messages/<int:user_id>", methods=["GET", "POST"])
@login_required
def chat(user_id):
    db = get_db()
    me = current_user()
    other = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not other:
        abort(404)

    if request.method == "POST":
        text = request.form.get("text", "").strip()
        if text:
            db.execute(
                "INSERT INTO messages (sender_id, receiver_id, text, created_at) VALUES (?, ?, ?, ?)",
                (me["id"], user_id, text, int(time.time())),
            )
            db.commit()
        return redirect(url_for("chat", user_id=user_id))

    thread = db.execute(
        """SELECT * FROM messages
           WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
           ORDER BY created_at ASC""",
        (me["id"], user_id, user_id, me["id"]),
    ).fetchall()
    return render_template("chat.html", other=other, thread=thread)


# ---------------------------------------------------------------- uploaded files
@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# ---------------------------------------------------------------- entrypoint
if not os.path.exists(DB_PATH):
    init_db()
else:
    init_db()  # safe: uses CREATE TABLE IF NOT EXISTS

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
