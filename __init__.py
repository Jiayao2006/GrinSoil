from flask import Flask, render_template, request, redirect, url_for, flash, session
import shelve
import bcrypt
from functools import wraps
from models import UserManager, User

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Create a global UserManager instance
user_manager = UserManager()

def get_admin_db():
    """Helper function to get the admin database"""
    return shelve.open('admin_db')

def init_admin():
    """Initialize default admin account if it doesn't exist"""
    with get_admin_db() as admin_db:
        if 'admin' not in admin_db:
            hashed_password = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt())
            admin_data = {
                'username': 'admin',
                'password': hashed_password,
                'role': 'admin'
            }
            admin_db['admin'] = admin_data
            print("Default admin account created")

# Decorator for login required
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in first', 'danger')
            return redirect(url_for('signup_login'))
        return f(*args, **kwargs)
    return decorated_function

# Decorator for admin-only routes
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in request.cookies:
            flash('Please log in as admin first', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup_login')
def signup_login():
    return render_template('signup_login.html')

@app.route('/signup', methods=['POST'])
def signup():
    username = request.form.get('username')
    password = request.form.get('password')
    phone = request.form.get('phone')
    role = request.form.get('role')
    
    # Input validation
    if not all([username, password, phone, role]):
        flash('All fields are required', 'danger')
        return redirect(url_for('signup_login'))
    
    if user_manager.create_user(username, password, phone, role):
        flash('Registration successful! Please login.', 'success')
    else:
        flash('Username already exists', 'danger')
    return redirect(url_for('signup_login'))

"""Login route"""
# Also ensure that your login route sets the session
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not all([username, password]):
        flash('Please provide both username and password', 'danger')
        return redirect(url_for('signup_login'))
    
    user = user_manager.authenticate_user(username, password)
    if user:
        # Set session variables
        session['username'] = username
        session['role'] = user.role
        flash('Login successful!', 'success')
        if user.role == 'Farmer':
            return redirect(url_for('farmer_dashboard'))
        else:
            return redirect(url_for('customer_dashboard'))
    
    flash('Invalid username or password', 'danger')
    return redirect(url_for('signup_login'))

"""Logout route"""
@app.route('/logout')
def logout():
    # Clear the session
    session.clear()
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('home'))


@app.route('/farmer_dashboard')
@login_required
def farmer_dashboard():
    if session.get('role') != 'Farmer':
        flash('Access denied', 'danger')
        return redirect(url_for('signup_login'))
    user = user_manager.get_user(session['username'])
    return render_template('farmer_dashboard.html', user=user)

@app.route('/customer_dashboard')
@login_required
def customer_dashboard():
    if session.get('role') != 'Customer':
        flash('Access denied', 'danger')
        return redirect(url_for('signup_login'))
    user = user_manager.get_user(session['username'])
    return render_template('customer_dashboard.html', user=user)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        with get_admin_db() as admin_db:
            if username not in admin_db:
                flash('Invalid admin credentials', 'danger')
                return redirect(url_for('admin_login'))
            
            admin_data = admin_db[username]
            if bcrypt.checkpw(password.encode('utf-8'), admin_data['password']):
                response = redirect(url_for('admin_dashboard'))
                response.set_cookie('admin_logged_in', 'true')
                flash('Welcome, Admin!', 'success')
                return response
            
        flash('Invalid admin credentials', 'danger')
        return redirect(url_for('admin_login'))
        
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    users = user_manager.get_all_users()
    return render_template('admin_dashboard.html', users=users)

@app.route('/admin/create_admin', methods=['POST'])
@admin_required
def create_admin():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not all([username, password]):
        flash('All fields are required', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    with get_admin_db() as admin_db:
        if username in admin_db:
            flash('Admin username already exists', 'danger')
            return redirect(url_for('admin_dashboard'))
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        admin_data = {
            'username': username,
            'password': hashed_password,
            'role': 'admin'
        }
        admin_db[username] = admin_data
    
    flash('New admin account created successfully', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_user/<username>')
@admin_required
def delete_user(username):
    if user_manager.delete_user(username):
        flash(f'User {username} has been deleted', 'success')
    else:
        flash('User not found', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/update_user/<username>', methods=['POST'])
@admin_required
def update_user(username):
    phone = request.form.get('phone')
    if user_manager.update_user(username, phone):
        flash(f'User {username} has been updated', 'success')
    else:
        flash('User not found', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/logout')
def admin_logout():
    response = redirect(url_for('admin_login'))
    response.delete_cookie('admin_logged_in')
    flash('Logged out successfully', 'success')
    return response

@app.route('/admin/users/<role>')
@admin_required
def filter_users(role):
    users = user_manager.get_users_by_role(role)
    return render_template('admin_dashboard.html', users=users)

@app.route('/admin/user/<username>')
@admin_required
def view_user(username):
    user = user_manager.get_user(username)
    if user:
        return render_template('user_details.html', user=user)
    flash('User not found', 'danger')
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    init_admin()
    app.run(debug=True)