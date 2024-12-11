from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///pubfitnessstudio.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)

# Define the database tables
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    deviceid = db.Column(db.String(255), nullable=True)
    last_sub_date = db.Column(db.Date, nullable=False)

class ActiveSession(db.Model):
    __tablename__ = 'active_sessions'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), db.ForeignKey('users.username'), nullable=False)
    deviceid = db.Column(db.String(255), nullable=False)
    sessionid = db.Column(db.String(255), nullable=False)
    last_login = db.Column(db.DateTime, nullable=False)

# Initialize the database
with app.app_context():
    db.create_all()

# Predefined admin credentials
ADMIN_CREDENTIALS = {"admin": "admin123"}

@app.route('/')
def login_page():
    return render_template('login.html')

@app.route('/admin_login', methods=['POST'])
def admin_login():
    username = request.form['username']
    password = request.form['password']

    if username in ADMIN_CREDENTIALS and ADMIN_CREDENTIALS[username] == password:
        session['admin'] = True
        return redirect(url_for('home'))
    else:
        return "Invalid credentials, please try again."

@app.route('/logout')
def logout():
    session.pop('admin', None)
    return redirect(url_for('login_page'))

@app.route('/home')
def home():
    if 'admin' not in session:
        return redirect(url_for('login_page'))

    users = User.query.all()
    return render_template('home.html', users=users)

@app.route('/create_user', methods=['POST'])
def create_user():
    if 'admin' not in session:
        return redirect(url_for('login_page'))

    username = request.form['username']
    password = request.form['password']
    last_sub_date = request.form['last_sub_date']
    
    if not last_sub_date:
        last_sub_date = (datetime.now() + timedelta(days=7)).strftime('%Y-%m-%d')

    if User.query.filter_by(username=username).first():
        return "User already exists."

    user = User(username=username, password=password, last_sub_date=datetime.strptime(last_sub_date, '%Y-%m-%d'))
    db.session.add(user)
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/update_user', methods=['POST'])
def update_user():
    if 'admin' not in session:
        return redirect(url_for('login_page'))

    username = request.form['username']
    password = request.form.get('password')
    last_sub_date = request.form.get('last_sub_date')

    user = User.query.filter_by(username=username).first()
    if not user:
        return "User not found."

    if password:
        user.password = password
    if last_sub_date:
        user.last_sub_date = datetime.strptime(last_sub_date, '%Y-%m-%d')

    db.session.commit()
    return redirect(url_for('home'))

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password']
    deviceid = data['deviceid']

    user = User.query.filter_by(username=username).first()

    if not user or user.password != password:
        return jsonify({"status": "Invalid credentials"}), 403

    if user.last_sub_date < datetime.today().date():
        return jsonify({"status": "Subscription expired"}), 403

    if user.deviceid and user.deviceid != deviceid:
        return jsonify({"status": "Login from a different device is not allowed"}), 403

    sessionid = f"session-{username}-{datetime.now().timestamp()}"

    if not user.deviceid:
        user.deviceid = deviceid

    session = ActiveSession(username=username, deviceid=deviceid, sessionid=sessionid, last_login=datetime.now())
    db.session.add(session)
    db.session.commit()

    days = (user.last_sub_date - datetime.today().date()).days

    return jsonify({
        "status": "Login Successful",
        "sessionid": sessionid,
        "AvailableDays": days
    })


@app.route('/cleanup_sessions', methods=['POST'])
def cleanup_sessions():
    if 'admin' not in session:
        return redirect(url_for('login_page'))

    threshold_date = datetime.now() - timedelta(days=30)
    expired_sessions = ActiveSession.query.filter(ActiveSession.last_login < threshold_date).all()

    for session in expired_sessions:
        db.session.delete(session)
    db.session.commit()
    return "Old sessions cleaned up."

# HTML templates
@app.route('/login.html')
def login_template():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Login</title>
    </head>
    <body>
        <h1>Admin Login</h1>
        <form action="/admin_login" method="post">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <button type="submit">Login</button>
        </form>
    </body>
    </html>
    '''

@app.route('/home.html')
def home_template():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Panel</title>
    </head>
    <body>
        <h1>Admin Panel</h1>
        <a href="/logout">Logout</a>
        <h2>Users</h2>
        <table border="1">
            <tr>
                <th>Username</th>
                <th>Password</th>
                <th>Device ID</th>
                <th>Last Subscription Date</th>
            </tr>
            {% for user in users %}
            <tr>
                <td>{{ user.username }}</td>
                <td>{{ user.password }}</td>
                <td>{{ user.deviceid }}</td>
                <td>{{ user.last_sub_date }}</td>
            </tr>
            {% endfor %}
        </table>

        <h2>Create New User</h2>
        <form action="/create_user" method="post">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            Last Subscription Date: <input type="date" name="last_sub_date"><br>
            <button type="submit">Create User</button>
        </form>

        <h2>Update User</h2>
        <form action="/update_user" method="post">
            Username: <input type="text" name="username"><br>
            Password (optional): <input type="password" name="password"><br>
            Last Subscription Date (optional): <input type="date" name="last_sub_date"><br>
            <button type="submit">Update User</button>
        </form>
    </body>
    </html>
    '''

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
