import sqlite3
from flask import Flask, render_template, redirect, request, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, TextAreaField
from wtforms.fields.datetime import DateField
from wtforms.validators import DataRequired, EqualTo
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = "super_secret_key"

login_manager = LoginManager(app)
login_manager.login_view = 'login'


# ----------------------
# Database Helper
# ----------------------
def get_db():
    conn = sqlite3.connect("events.db")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()

    # Users
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )""")

    # Events
    c.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        date TEXT NOT NULL,
        location TEXT NOT NULL,
        description TEXT NOT NULL,
        organizer_id INTEGER NOT NULL,
        FOREIGN KEY (organizer_id) REFERENCES users(id)
    )""")

    # Event signups (many-to-many)
    c.execute("""
    CREATE TABLE IF NOT EXISTS event_signups (
        user_id INTEGER,
        event_id INTEGER,
        PRIMARY KEY (user_id, event_id),
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (event_id) REFERENCES events(id)
    )""")

    conn.commit()
    conn.close()


# ----------------------
# Forms
# ----------------------
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class EventForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    date = DateField('Date', format='%m-%d-%Y', validators=[DataRequired()])
    location = StringField('Location', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    submit = SubmitField('Submit')


# ----------------------
# Flask-Login User
# ----------------------
class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password


@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    if user:
        return User(user["id"], user["username"], user["password"])
    return None


# ----------------------
# Routes
# ----------------------
@app.route('/')
def landing_page():
    return render_template('landing-page.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data)
        conn = get_db()
        try:
            conn.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                         (form.username.data, hashed_pw))
            conn.commit()
            flash("Account created successfully!", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username already taken.", "danger")
        finally:
            conn.close()
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username=?", (form.username.data,)).fetchone()
        conn.close()
        if user and check_password_hash(user["password"], form.password.data):
            login_user(User(user["id"], user["username"], user["password"]))
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password", "danger")
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db()
    events = conn.execute("SELECT * FROM events").fetchall()
    conn.close()
    return render_template('dashboard.html', events=events, user=current_user)


@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_event():
    form = EventForm()
    if form.validate_on_submit():
        conn = get_db()
        conn.execute("INSERT INTO events (title, date, location, description, organizer_id) VALUES (?, ?, ?, ?, ?)",
                     (form.title.data, form.date.data.strftime("%Y-%m-%d"),
                      form.location.data, form.description.data, current_user.id))
        conn.commit()
        conn.close()
        flash("Event created successfully!", "success")
        return redirect(url_for('list_events'))
    return render_template('create_event.html', form=form)


@app.route('/list-events')
@login_required
def list_events():
    conn = get_db()
    events = conn.execute("SELECT * FROM events WHERE organizer_id=?", (current_user.id,)).fetchall()
    conn.close()
    return render_template('events.html', events=events)


@app.route('/event/<int:event_id>/signup')
@login_required
def signup_event(event_id):
    conn = get_db()
    already = conn.execute("SELECT * FROM event_signups WHERE user_id=? AND event_id=?",
                           (current_user.id, event_id)).fetchone()
    if not already:
        conn.execute("INSERT INTO event_signups (user_id, event_id) VALUES (?, ?)",
                     (current_user.id, event_id))
        conn.commit()
        flash("Signed up successfully!", "success")
    else:
        flash("You are already signed up for this event.", "warning")
    conn.close()
    return redirect(url_for('list_events'))


@app.route('/event/<int:event_id>/attendees')
@login_required
def view_attendees(event_id):
    conn = get_db()
    attendees = conn.execute("""
        SELECT u.username FROM users u
        JOIN event_signups es ON u.id = es.user_id
        WHERE es.event_id = ?
    """, (event_id,)).fetchall()
    conn.close()
    return render_template('view_attendees.html', attendees=attendees)


@app.route('/search')
@login_required
def search_events():
    query = request.args.get('query', '')
    conn = get_db()
    events = conn.execute("""
        SELECT * FROM events
        WHERE title LIKE ? OR location LIKE ? OR description LIKE ?
    """, (f"%{query}%", f"%{query}%", f"%{query}%")).fetchall()
    conn.close()
    return render_template('search_events.html', events=events, query=query)


@app.route('/delete_event/<int:event_id>', methods=['POST'])
@login_required
def delete_event(event_id):
    conn = get_db()
    conn.execute("DELETE FROM events WHERE id=? AND organizer_id=?", (event_id, current_user.id))
    conn.commit()
    conn.close()
    flash("Event deleted successfully!", "success")
    return redirect(url_for('list_events'))


@app.route("/profile/<int:user_id>")
@login_required
def user_profilepage(user_id):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    created_events = conn.execute("SELECT * FROM events WHERE organizer_id=?", (user_id,)).fetchall()
    signed_up_events = conn.execute("""
        SELECT e.* FROM events e
        JOIN event_signups es ON e.id = es.event_id
        WHERE es.user_id=?
    """, (user_id,)).fetchall()
    conn.close()
    return render_template("user_profilepage.html", user=user,
                           created_events=created_events, signedup_events=signed_up_events)


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        conn = get_db()
        row = conn.execute("SELECT * FROM users WHERE id=?", (current_user.id,)).fetchone()

        if not check_password_hash(row["password"], current_password):
            flash("Current password is incorrect.", "danger")
            return redirect(url_for("change_password"))

        if new_password != confirm_password:
            flash("New passwords do not match.", "danger")
            return redirect(url_for("change_password"))

        conn.execute("UPDATE users SET password=? WHERE id=?",
                     (generate_password_hash(new_password), current_user.id))
        conn.commit()
        conn.close()
        flash("Password updated successfully!", "success")
        return redirect(url_for("user_profilepage", user_id=current_user.id))

    return render_template("change_password.html")


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
