import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL(os.getenv("DATABASE_URL"))

@app.route("/")
@login_required
def index():
    user = session.get("user_id")
    tasks = db.execute(
        "SELECT * FROM list WHERE user_id = ? AND active IS TRUE", user)
    if len(tasks) == 0:
        flash("Your ToDo list is empty")

    return render_template("index.html", tasks=tasks)


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        task = request.form.get("task")

        if not task:
            flash("task can't be blank")
            return redirect("/")

        user = session.get("user_id")
        add = db.execute("INSERT INTO list (user_id, task) values (?,?);", user, task,)
        tasks = db.execute(
            "SELECT * FROM list WHERE user_id = ? AND active IS TRUE", user)
        if len(tasks) == 0:
            flash("Your ToDo list is empty")
        return render_template("index.html", tasks=tasks)

    else:
        return redirect("/")


@app.route("/history")
@login_required
def history():
    user = session.get("user_id")
    tasks = db.execute("SELECT * FROM list WHERE user_id=?", user,)
    return render_template("history.html", tasks=tasks)

@app.route("/clear")
@login_required
def clear():
    user = session.get("user_id")
    tasks = db.execute("UPDATE list SET active = false WHERE done = true AND user_id=?", user,)
    flash("Cleared!")
    return redirect ("/")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            flash("Enter a valid username")
            return render_template("login.html")

        # Ensure password was submitted
        elif not request.form.get("password"):
            flash("Enter a valid password")
            return render_template("login.html")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            flash("username/password is incorrect")
            return render_template("login.html")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        rows = db.execute("SELECT * FROM users WHERE username = ?", username,)

        if not request.form.get("username"):
            flash("must provide username")
            return render_template("login.html")

        elif not request.form.get("password"):
            flash("must provide password")
            return render_template("login.html")

        elif not request.form.get("confirmation"):
            flash("must provide password confirmation")
            return render_template("login.html")

        elif not password == confirmation:
            flash("passwords must match")
            return render_template("login.html")

        elif len(rows) > 0:
            flash("username already taken")
            return render_template("login.html")

        else:
            hash = generate_password_hash(password, method="pbkdf2:sha256", salt_length=8)
            rows = db.execute("INSERT INTO users (username, hash) VALUES (?, ?) ", username, hash,)
            # Remember which user has logged in
            session["user_id"] = rows
            # Redirect user to home page
            flash('Registered!')
            return redirect("/")
    else:
        return render_template("/register.html"), 200

@app.route("/check/<id>", methods=["GET"])
@login_required
def check(id):
    user = session.get("user_id")
    task = db.execute("SELECT * FROM list WHERE id=?", id)
    row = len(task)
    if row >= 1:
        if task[0]["done"] == 0:
            db.execute("UPDATE list SET done = true WHERE id=?", id,)
        else:
            db.execute("UPDATE list SET done = false WHERE id=?", id,)

        tasks = db.execute("SELECT * FROM list WHERE active=true and user_id=?", user)
        return render_template("index.html", tasks=tasks)
    else:
        tasks = db.execute("SELECT * FROM list WHERE active=true and user_id=?", user)
        flash("Task Error")
        return render_template("index.html", tasks=tasks)

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
        flash(e.name)
        return redirect("/"), e.code



# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
