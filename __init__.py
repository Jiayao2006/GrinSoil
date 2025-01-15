from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import shelve
import bcrypt
from functools import wraps
from models import *
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Decorator for login required
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in first', 'danger')
            return redirect(url_for('signup_login'))
        return f(*args, **kwargs)
    return decorated_function

"""Reviews Section"""
# Add to __init__.py after other imports
review_manager = ReviewManager()

# Add these routes
@app.route('/reviews')
def reviews():
    all_reviews = review_manager.get_all_reviews()
    return render_template('reviews.html', reviews=all_reviews)

@app.route('/my-reviews')
@login_required
def my_reviews():
    user_reviews = review_manager.get_user_reviews(session['username'])
    return render_template('my_reviews.html', reviews=user_reviews)

@app.route('/review/add', methods=['POST'])
@login_required
def add_review():
    content = request.form.get('content')
    if not content:
        flash('Review content is required', 'danger')
        return redirect(url_for('my_reviews'))
    
    review_manager.create_review(content, session['username'])
    flash('Review added successfully', 'success')
    return redirect(url_for('my_reviews'))

@app.route('/review/update/<review_id>', methods=['POST'])
@login_required
def update_review(review_id):
    content = request.form.get('content')
    review = review_manager.get_review(review_id)
    
    if not review or review.author != session['username']:
        flash('Review not found or unauthorized', 'danger')
        return redirect(url_for('my_reviews'))
    
    if review_manager.update_review(review_id, content):
        flash('Review updated successfully', 'success')
    else:
        flash('Failed to update review', 'danger')
    return redirect(url_for('my_reviews'))

@app.route('/review/delete/<review_id>')
@login_required
def delete_review(review_id):
    review = review_manager.get_review(review_id)
    
    if not review or review.author != session['username']:
        flash('Review not found or unauthorized', 'danger')
        return redirect(url_for('my_reviews'))
    
    if review_manager.delete_review(review_id):
        flash('Review deleted successfully', 'success')
    else:
        flash('Failed to delete review', 'danger')
    return redirect(url_for('my_reviews'))

# Update the about route to include reviews
@app.route('/about')
def about():
    """Public route for About page - anyone can view reviews"""
    all_reviews = review_manager.get_all_reviews()
    # Sort reviews by created_at date, most recent first
    sorted_reviews = sorted(all_reviews, key=lambda x: datetime.strptime(x.created_at, "%Y-%m-%d %H:%M:%S"), reverse=True)
    return render_template('about.html', reviews=sorted_reviews)

@app.route('/api/reviews')
def get_reviews():
    """Public API endpoint to get all reviews"""
    all_reviews = review_manager.get_all_reviews()
    sorted_reviews = sorted(all_reviews, key=lambda x: datetime.strptime(x.created_at, "%Y-%m-%d %H:%M:%S"), reverse=True)
    return jsonify([review.to_dict() for review in sorted_reviews])


"""admin management"""
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

"""farmer and customer dashboard"""
@app.route('/farmer_dashboard')
@login_required
def farmer_dashboard():
    if session.get('role') != 'Farmer':
        flash('Access denied', 'danger')
        return redirect(url_for('signup_login'))
    user = user_manager.get_user(session['username'])
    counts = product_manager.get_status_counts(session['username'])
    return render_template('farmer_dashboard.html', user=user, product_counts=counts)

@app.route('/customer_dashboard')
@login_required
def customer_dashboard():
    if session.get('role') != 'Customer':
        flash('Access denied', 'danger')
        return redirect(url_for('signup_login'))
    user = user_manager.get_user(session['username'])
    counts = product_manager.get_status_counts(session['username'])
    return render_template('customer_dashboard.html', user=user, product_counts=counts)

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

"""food expiry tracker"""
product_manager = ProductManager()

@app.route('/farmer/expiry-tracker')
@login_required
def farmer_expiry_tracker():
    if session.get('role') != 'Farmer':
        flash('Access denied', 'danger')
        return redirect(url_for('home'))
    products = product_manager.get_user_products(session['username'])
    return render_template('expiry_tracker.html', products=products, user_role='Farmer')

@app.route('/customer/expiry-tracker')
@login_required
def customer_expiry_tracker():
    if session.get('role') != 'Customer':
        flash('Access denied', 'danger')
        return redirect(url_for('home'))
    products = product_manager.get_user_products(session['username'])
    return render_template('expiry_tracker.html', products=products, user_role='Customer')

@app.route('/product/add', methods=['POST'])
@login_required
def add_product():
    name = request.form.get('name')
    expiry_date = request.form.get('expiry_date')
    
    if not all([name, expiry_date]):
        flash('All fields are required', 'danger')
        return redirect(url_for(f'{session["role"].lower()}_expiry_tracker'))
    
    product_manager.create_product(name, expiry_date, session['username'])
    flash('Product added successfully', 'success')
    return redirect(url_for(f'{session["role"].lower()}_expiry_tracker'))

@app.route('/product/update-status/<product_id>', methods=['POST'])
@login_required
def update_product_status(product_id):
    new_status = request.form.get('status')
    if new_status not in ['fresh', 'expiring-soon', 'expired', 'eaten']:
        flash('Invalid status', 'danger')
        return redirect(url_for(f'{session["role"].lower()}_expiry_tracker'))
        
    if product_manager.update_product_status(product_id, new_status):
        flash('Product status updated successfully', 'success')
    else:
        flash('Failed to update product status', 'danger')
    return redirect(url_for(f'{session["role"].lower()}_expiry_tracker'))

@app.route('/product/delete/<product_id>')
@login_required
def delete_product(product_id):
    if product_manager.delete_product(product_id):
        flash('Product deleted successfully', 'success')
    else:
        flash('Failed to delete product', 'danger')
    return redirect(url_for(f'{session["role"].lower()}_expiry_tracker'))

@app.route('/product/update/<product_id>', methods=['POST'])
@login_required
def update_product(product_id):
    name = request.form.get('name')
    expiry_date = request.form.get('expiry_date')
    
    if not all([name, expiry_date]):
        flash('All fields are required', 'danger')
        return redirect(url_for(f'{session["role"].lower()}_expiry_tracker'))
    
    if product_manager.update_product(product_id, name, expiry_date):
        flash('Product updated successfully', 'success')
    else:
        flash('Failed to update product', 'danger')
    return redirect(url_for(f'{session["role"].lower()}_expiry_tracker'))

@app.route('/product/get/<product_id>')
@login_required
def get_product(product_id):
    product = product_manager.get_product(product_id)
    if product and product.owner == session['username']:
        return jsonify(product.to_dict())
    return jsonify({'error': 'Product not found'}), 404

if __name__ == '__main__':
    init_admin()
    app.run(debug=True)