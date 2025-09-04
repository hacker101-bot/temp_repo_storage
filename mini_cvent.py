
from flask import Flask, render_template, redirect, request, session, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from sqlalchemy.orm import backref
from wtforms import StringField, SubmitField, PasswordField, BooleanField, TextAreaField
from wtforms.fields.datetime import DateField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)

app.config['SECRET_KEY'] = "super_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///events.db'
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Many-to-Many relationship table
# Association table
event_signups = db.Table(
    'event_signups',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('event_id', db.Integer, db.ForeignKey('event.id'), primary_key=True)
)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    created_events = db.relationship('Event', backref='creator', lazy=True)

    # 👇 use event_signups only
    signed_up_events = db.relationship(
        'Event',
        secondary=event_signups,
        back_populates='attendees'
    )



class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    location = db.Column(db.String(64), nullable=False)
    description = db.Column(db.Text, nullable=False)

    organizer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    organizer = db.relationship('User', backref="organized_events")

    # 👇 connect to User.signed_up_events
    attendees = db.relationship(
        'User',
        secondary=event_signups,
        back_populates='signed_up_events'
    )


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
    date = DateField('Date', format='%Y-%m-%d', validators=[DataRequired()])
    location = StringField('Location', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    submit = SubmitField('Submit')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Account created successfully", 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password", "danger")
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/list-events', methods=['GET'])
@login_required
def list_events():
    q = request.args.get('q', '').strip()  # keep search working if you added it
    query = Event.query.filter_by(organizer_id=current_user.id)

    if q:
        like = f"%{q}%"
        query = query.filter(
            (Event.title.ilike(like)) |
            (Event.location.ilike(like)) |
            (Event.description.ilike(like))
        )

    events = query.order_by(Event.date.asc()).all()
    return render_template('events.html', events=events, only_mine=True)

@app.route("/create", methods=['GET', 'POST'])
@login_required
def create_event():
    form = EventForm()
    if form.validate_on_submit():
        new_event = Event(
            title=form.title.data,
            date=form.date.data,
            location=form.location.data,
            description=form.description.data,
            organizer=current_user
        )
        db.session.add(new_event)
        db.session.commit()
        flash("Event created successfully", "success")
        return redirect(url_for('list_events'))
    return render_template('create_event.html', title='Create Event', form=form)

@app.route('/event/<int:event_id>/signup')
@login_required
def signup_event(event_id):
    event = Event.query.get_or_404(event_id)
    if current_user not in event.attendees:
        event.attendees.append(current_user)
        db.session.commit()
        flash("You have successfully signed up for this event!", "success")
    else:
        flash("You are already signed up for this event.", "danger")
    return redirect(url_for('user_profilepage', user_id=current_user.id))

@app.route('/dashboard')
@login_required
def dashboard():
    ongoing_events = Event.query.filter(Event.date).all()
    return render_template('dashboard.html', events=ongoing_events, user=current_user)

@app.route('/')
def landing_page():
    return render_template('landing-page.html')

@app.route('/event/<int:event_id>/attendees')
@login_required
def view_attendees(event_id):
    event = Event.query.get_or_404(event_id)
    if event.organizer != current_user:
        flash("You are not authorized to see this event attendance!", "danger")
        return redirect(url_for('dashboard'))
    return render_template('view_attendees.html', event=event, attendees=event.attendees)
@app.route('/search', methods=['GET', 'POST'])
@login_required
def search_events():
    query = request.args.get('query')
    if query:
        events = Event.query.filter(Event.title.ilike(query),
                                    Event.location.ilike(query),
                                    Event.description.ilike(query)).all()
    else:
        events = Event.query.all()
    return render_template('search_events.html', events=events,query=query)

@app.route('/delete_event/<int:event_id>', methods=['POST'])
@login_required
def delete_event(event_id):
    event = Event.query.get_or_404(event_id)

    # Security check: only the organizer can delete
    if event.organizer_id != current_user.id:
        flash("You are not authorized to delete this event.", "danger")
        return redirect(url_for('list_events'))

    db.session.delete(event)
    db.session.commit()
    flash("Event deleted successfully!", "success")
    return redirect(url_for('list_events'))

@app.route("/profile/<int:user_id>")
@login_required
def user_profilepage(user_id):
    user = User.query.get_or_404(user_id)
   # created_events = Event.query.filter_by(organizer_id=user.id).all()

    created_events = user.created_events  # works because of backref
    signed_up_events = user.signed_up_events
    return render_template(
        "user_profilepage.html",
        user=user,
        created_events=created_events,
        signedup_events=signed_up_events,
    )
@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        # Verify old password
        if not check_password_hash(current_user.password, current_password):
            flash("Current password is incorrect.", "danger")
            return redirect(url_for("change_password"))

        # Check match
        if new_password != confirm_password:
            flash("New passwords do not match.", "danger")
            return redirect(url_for("change_password"))

        # Update password
        current_user.password = generate_password_hash(new_password)
        db.session.commit()

        flash("Password updated successfully!", "success")
        return redirect(url_for("user_profilepage", user_id=current_user.id))

    return render_template("change_password.html")


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
