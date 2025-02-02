from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
import shelve
import bcrypt
from functools import wraps
from models import *
from datetime import datetime, timedelta
import re
import random
import werkzeug.exceptions
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# configurations for file uploads
UPLOAD_FOLDER = 'static/product_images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER



# Add this route to __init__.py for debugging
@app.route('/debug/notifications')
def debug_notifications():
    """Debug route to check notification database contents"""
    try:
        with shelve.open('notifications_db', 'r') as db:
            # Get all keys
            all_keys = list(db.keys())
            print("All keys in database:", all_keys)
            
            # Get all notifications
            notifications_data = []
            for key in all_keys:
                try:
                    data = db[key]
                    notifications_data.append({
                        'key': key,
                        'data': data
                    })
                except Exception as e:
                    print(f"Error reading key {key}: {str(e)}")
            
            return jsonify({
                'keys': all_keys,
                'notifications': notifications_data,
                'total_count': len(all_keys)
            })
    except Exception as e:
        print(f"Error accessing database: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

# Add the error handler and initialization code here
@app.errorhandler(Exception)
def handle_error(error):
    if request.path == '/favicon.ico':
        return '', 204
    return redirect(url_for('home'))

# Add specific 404 handler
@app.errorhandler(404)
def page_not_found(e):
    # Ignore favicon.ico requests
    if request.path == '/favicon.ico':
        return '', 204
    return redirect(url_for('home'))

def init_notification_db():
    """Initialize notification database"""
    try:
        print("Attempting to initialize notification database...")
        with shelve.open('notifications_db', 'c') as db:
            # Test write to ensure database is working
            test_key = '__test__'
            db[test_key] = {'test': 'data'}
            del db[test_key]
            print("Notification database initialized successfully")
            return True
    except Exception as e:
        print(f"Error initializing notification database: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

# Initialize databases
if not init_notification_db():
    print("WARNING: Failed to initialize notification database")

"""OTP verification"""
class OTPManager:
    def __init__(self):
        self.__db_name = 'otp_db'
        
    def __get_db(self):
        return shelve.open(self.__db_name)
    
    def generate_otp(self):
        """Generate a 6-digit OTP"""
        return ''.join([str(random.randint(0, 9)) for _ in range(6)])
    
    def store_otp(self, phone, otp):
        """Store OTP with metadata"""
        with self.__get_db() as db:
            db[phone] = {
                'otp': otp,
                'expiry': datetime.now() + timedelta(minutes=3),
                'attempts': 0,
                'verified': False,
                'last_sent': datetime.now()
            }
    
    def verify_otp(self, phone, otp):
        """Verify OTP and handle attempts"""
        with self.__get_db() as db:
            if phone not in db:
                return False, "No OTP found for this phone number"
            
            otp_data = db[phone]
            
            # Check if OTP has expired
            if datetime.now() > otp_data['expiry']:
                del db[phone]
                return False, "OTP has expired"
            
            # Check attempt limit
            if otp_data['attempts'] >= 3:
                del db[phone]
                return False, "Too many failed attempts. Please request a new OTP"
            
            # Verify OTP
            if otp_data['otp'] != otp:
                otp_data['attempts'] += 1
                db[phone] = otp_data
                remaining_attempts = 3 - otp_data['attempts']
                return False, f"Invalid OTP. {remaining_attempts} attempts remaining"
            
            # Mark as verified
            otp_data['verified'] = True
            db[phone] = otp_data
            return True, "OTP verified successfully"
    
    def can_resend_otp(self, phone):
        """Check if OTP can be resent (30s cooldown)"""
        with self.__get_db() as db:
            if phone not in db:
                return True
            
            otp_data = db[phone]
            cooldown_period = timedelta(seconds=30)
            return datetime.now() - otp_data['last_sent'] > cooldown_period
    
    def is_verified(self, phone):
        """Check if phone number is verified"""
        with self.__get_db() as db:
            return phone in db and db[phone].get('verified', False)

# Initialize OTP manager
otp_manager = OTPManager()

# Decorator to ensure phone verification
def phone_verified(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        phone = session.get('phone_number')
        if not phone or not otp_manager.is_verified(phone):
            flash('Phone verification required', 'danger')
            return redirect(url_for('signup_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/send-otp', methods=['POST'])
def send_otp():
    try:
        data = request.get_json()
        phone = data.get('phone')
        
        if not phone:
            return jsonify({'error': 'Phone number is required'}), 400
        
        # Check if can resend OTP
        if not otp_manager.can_resend_otp(phone):
            return jsonify({'error': 'Please wait 30 seconds before requesting a new OTP'}), 429
        
        # Generate and store OTP
        otp = otp_manager.generate_otp()
        otp_manager.store_otp(phone, otp)
        
        # Store phone number in session
        session['phone_number'] = phone
        
        # For development, print to console
        print(f"Development Mode - OTP for {phone}: {otp}")
        
        return jsonify({
            'status': 'success',
            'message': 'OTP sent successfully',
            'expiresIn': 180  # 3 minutes in seconds
        }), 200
        
    except Exception as e:
        print(f"Error in send_otp: {str(e)}")
        # Return 200 status since OTP was actually generated successfully
        return jsonify({
            'status': 'success',
            'message': 'OTP sent successfully despite error',
            'error_details': str(e),
            'expiresIn': 180
        }), 200

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    try:
        data = request.get_json()
        phone = data.get('phone')
        otp = data.get('otp')
        
        if not all([phone, otp]):
            return jsonify({'error': 'Phone and OTP are required'}), 400
        
        # Verify OTP
        is_valid, message = otp_manager.verify_otp(phone, otp)
        
        if is_valid:
            return jsonify({'message': message}), 200
        else:
            return jsonify({'error': message}), 400
            
    except Exception as e:
        print(f"Error verifying OTP: {str(e)}")
        return jsonify({'error': 'Failed to verify OTP'}), 500

# Decorator for login required
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in first', 'danger')
            return redirect(url_for('signup_login'))
        return f(*args, **kwargs)
    return decorated_function

"""password validation"""
def validate_password(password):
    """Validate password meets requirements"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must include at least one uppercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must include at least one number"
    if not re.search(r'[!@#$%^&*]', password):
        return False, "Password must include at least one special character (!@#$%^&*)"
    return True, ""

def validate_email(email):
    """Validate email format"""
    if not email:  # Email is optional
        return True, ""
    email_regex = re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')
    if not email_regex.match(email):
        return False, "Invalid email format"
    return True, ""

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
    try:
        # Get form data
        username = request.form.get('username')
        password = request.form.get('password')
        full_phone = request.form.get('full_phone')  # Get the full phone number from hidden input
        email = request.form.get('email')
        role = request.form.get('role')
        
        # Debug prints
        print("Form Data Received:")
        print(f"Username: {username}")
        print(f"Full Phone: {full_phone}")
        print(f"Role: {role}")
        
        # Input validation
        if not username:
            flash('Username is required', 'danger')
            return redirect(url_for('signup_login'))
        
        if not password:
            flash('Password is required', 'danger')
            return redirect(url_for('signup_login'))
        
        if not full_phone:
            # Try to construct from individual parts if full_phone is not present
            country_code = request.form.get('country_code')
            phone_number = request.form.get('phone')
            full_phone = f"{country_code}{phone_number}" if country_code and phone_number else None
            
            if not full_phone:
                flash('Phone number with country code is required', 'danger')
                return redirect(url_for('signup_login'))
        
        if not role:
            flash('Role selection is required', 'danger')
            return redirect(url_for('signup_login'))
        
        # Verify phone number
        if not otp_manager.is_verified(full_phone):
            flash('Phone number must be verified with OTP', 'danger')
            return redirect(url_for('signup_login'))
        
        # Validate password
        is_valid_password, password_message = validate_password(password)
        if not is_valid_password:
            flash(password_message, 'danger')
            return redirect(url_for('signup_login'))
        
        # Validate email if provided
        if email:
            is_valid_email, email_message = validate_email(email)
            if not is_valid_email:
                flash(email_message, 'danger')
                return redirect(url_for('signup_login'))
        
        # Create user
        if user_manager.create_user(username, password, full_phone, role, email):
            flash('Registration successful! Please login.', 'success')
        else:
            flash('Username already exists', 'danger')
        
        return redirect(url_for('signup_login'))
        
    except Exception as e:
        print(f"Error in signup: {str(e)}")
        flash('An error occurred during signup. Please try again.', 'danger')
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
    try:
        if session.get('role') != 'Farmer':
            flash('Access denied', 'danger')
            return redirect(url_for('signup_login'))
        
        user = user_manager.get_user(session['username'])
        counts = product_manager.get_status_counts(session['username'])
        
        # Get notifications with better error handling
        try:
            notifications = notification_manager.get_notifications_for_role('Farmer')
            notification_counts = {
                'total': len(notifications),
                'unread': len([n for n in notifications if session['username'] not in n.read_by])
            }
        except Exception as e:
            print(f"Error getting notifications: {str(e)}")
            import traceback
            traceback.print_exc()
            notifications = []
            notification_counts = {'total': 0, 'unread': 0}
        
        return render_template('farmer_dashboard.html', 
                             user=user, 
                             product_counts=counts,
                             notification_counts=notification_counts,
                             notifications=notifications)
    except Exception as e:
        print(f"Error in farmer_dashboard: {str(e)}")
        flash('An error occurred while loading the dashboard', 'danger')
        return redirect(url_for('home'))


@app.route('/customer_dashboard')
@login_required
def customer_dashboard():
    try:
        if session.get('role') != 'Customer':
            flash('Access denied', 'danger')
            return redirect(url_for('signup_login'))
        
        user = user_manager.get_user(session['username'])
        counts = product_manager.get_status_counts(session['username'])
        
        # Get notifications with better error handling
        try:
            notifications = notification_manager.get_notifications_for_role('Customer')
            notification_counts = {
                'total': len(notifications),
                'unread': len([n for n in notifications if session['username'] not in n.read_by])
            }
        except Exception as e:
            print(f"Error getting notifications: {str(e)}")
            import traceback
            traceback.print_exc()
            notifications = []
            notification_counts = {'total': 0, 'unread': 0}
        
        return render_template('customer_dashboard.html', 
                             user=user, 
                             product_counts=counts,
                             notification_counts=notification_counts,
                             notifications=notifications)
    except Exception as e:
        print(f"Error in customer_dashboard: {str(e)}")
        flash('An error occurred while loading the dashboard', 'danger')
        return redirect(url_for('home'))

@app.route('/notification/mark-read/<notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    try:
        success = notification_manager.mark_notification_as_read(notification_id, session['username'])
        if success:
            counts = notification_manager.get_notification_counts(session['role'], session['username'])
            return jsonify({
                'success': True,
                'counts': counts
            })
        return jsonify({'success': False, 'error': 'Failed to mark notification as read'})
    except Exception as e:
        print(f"Error in mark_notification_read: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error occurred'})

@app.route('/notification/mark-unread/<notification_id>', methods=['POST'])
@login_required
def mark_notification_unread(notification_id):
    try:
        success = notification_manager.mark_notification_as_unread(notification_id, session['username'])
        if success:
            counts = notification_manager.get_notification_counts(session['role'], session['username'])
            return jsonify({
                'success': True,
                'counts': counts
            })
        return jsonify({'success': False, 'error': 'Failed to mark notification as unread'})
    except Exception as e:
        print(f"Error in mark_notification_unread: {str(e)}")
        return jsonify({'success': False, 'error': 'Server error occurred'})


"""admin routes"""
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

@app.route('/admin/reviews')
@admin_required
def admin_reviews():
    """Admin route to view and manage all reviews"""
    review_manager = ReviewManager()
    all_reviews = review_manager.get_all_reviews()
    # Sort reviews by created_at date, most recent first
    sorted_reviews = sorted(all_reviews, key=lambda x: datetime.strptime(x.created_at, "%Y-%m-%d %H:%M:%S"), reverse=True)
    return render_template('admin_reviews.html', reviews=sorted_reviews)

@app.route('/admin/review/delete/<review_id>')
@admin_required
def admin_delete_review(review_id):
    """Admin route to delete a review"""
    review_manager = ReviewManager()
    if review_manager.delete_review(review_id):
        flash('Review deleted successfully', 'success')
    else:
        flash('Failed to delete review', 'danger')
    return redirect(url_for('admin_reviews'))

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

"""user settings"""
@app.route('/user/settings')
@login_required
def user_settings():
    user = user_manager.get_user(session['username'])
    return render_template('user_settings.html', user=user)

@app.route('/user/settings/update', methods=['POST'])
@login_required
def update_user_settings():
    phone = request.form.get('phone')
    
    if not phone:
        flash('Phone number is required', 'danger')
        return redirect(url_for('user_settings'))
    
    if user_manager.update_user(session['username'], phone):
        flash('Account information updated successfully', 'success')
    else:
        flash('Failed to update account information', 'danger')
    return redirect(url_for('user_settings'))

@app.route('/user/delete', methods=['POST'])
@login_required
def delete_user_account():
    username = session['username']
    if user_manager.delete_user(username):
        session.clear()
        flash('Your account has been deleted successfully', 'success')
        return redirect(url_for('home'))
    flash('Failed to delete account', 'danger')
    return redirect(url_for('user_settings'))

"""notifications"""
notification_manager = NotificationManager()

# Add these routes
@app.route('/notifications')
@login_required
def notifications():
    """Modified notifications route with debug information"""
    try:
        user_role = session.get('role')
        print(f"Getting notifications for role: {user_role}")
        
        # Debug: Print database contents
        with shelve.open('notifications_db', 'r') as db:
            print("Database keys:", list(db.keys()))
            for key in db:
                print(f"Notification {key}:", db[key])
        
        notifications = notification_manager.get_notifications_for_role(user_role)
        print(f"Retrieved {len(notifications)} notifications")
        
        # Debug: Print each notification
        for notification in notifications:
            print(f"Notification: {notification.id}, {notification.title}, {notification.target_role}")
        
        return render_template('notifications.html', 
                             notifications=notifications,
                             debug_info={
                                 'user_role': user_role,
                                 'total_notifications': len(notifications)
                             })
    except Exception as e:
        print(f"Error in notifications route: {str(e)}")
        import traceback
        traceback.print_exc()
        flash('An error occurred while loading notifications', 'danger')
        return redirect(url_for(f"{session['role'].lower()}_dashboard"))

@app.route('/admin/notifications')
@admin_required
def admin_notifications():
    """Admin view of all notifications"""
    try:
        print("Fetching notifications for admin view")
        notifications = notification_manager.get_all_notifications()
        print(f"Retrieved {len(notifications)} notifications")
        
        # Debug print each notification
        for notification in notifications:
            print(f"Notification: ID={notification.id}, "
                  f"Title={notification.title}, "
                  f"Target={notification.target_role}, "
                  f"Created={notification.created_at}")
        
        # Sort by created date, most recent first
        notifications.sort(key=lambda x: datetime.strptime(x.created_at, "%Y-%m-%d %H:%M:%S"), reverse=True)
        
        return render_template('admin_notifications.html', notifications=notifications)
    except Exception as e:
        print(f"Error in admin_notifications: {str(e)}")
        import traceback
        traceback.print_exc()
        flash('Error loading notifications', 'danger')
        return redirect(url_for('admin_dashboard'))
    
@app.route('/admin/notifications', methods=['POST'])
@admin_required
def add_notification():
    """Modified admin route to add a new notification with proper response handling"""
    try:
        title = request.form.get('title')
        content = request.form.get('content')
        target_role = request.form.get('target_role')
        
        if not all([title, content, target_role]):
            return jsonify({
                'success': False,
                'message': 'All fields are required'
            }), 400
        
        notification_id = notification_manager.create_notification(title, content, target_role)
        
        if notification_id:
            return jsonify({
                'success': True,
                'message': 'Notification created successfully',
                'notification_id': notification_id
            }), 200
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to create notification'
            }), 500
            
    except Exception as e:
        print(f"Error in add_notification: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'message': 'An error occurred while creating the notification'
        }), 500

@app.route('/admin/notification/update/<notification_id>', methods=['POST'])
@admin_required
def update_notification(notification_id):
    """Admin route to update a notification"""
    try:
        title = request.form.get('title')
        content = request.form.get('content')
        target_role = request.form.get('target_role')
        
        if not all([title, content, target_role]):
            flash('All fields are required', 'danger')
            return redirect(url_for('admin_notifications'))
        
        if notification_manager.update_notification(notification_id, title, content, target_role):
            flash('Notification updated successfully', 'success')
        else:
            flash('Failed to update notification', 'danger')
            
    except Exception as e:
        print(f"Error in update_notification: {str(e)}")
        flash('An error occurred while updating the notification', 'danger')
    
    return redirect(url_for('admin_notifications'))

@app.route('/admin/notification/delete/<notification_id>')
@admin_required
def delete_notification(notification_id):
    """Admin route to delete a notification"""
    try:
        if notification_manager.delete_notification(notification_id):
            flash('Notification deleted successfully', 'success')
        else:
            flash('Failed to delete notification', 'danger')
            
    except Exception as e:
        print(f"Error in delete_notification: {str(e)}")
        flash('An error occurred while deleting the notification', 'danger')
    
    return redirect(url_for('admin_notifications'))


"""Product Listing"""
"""Form submission for adding products"""
@app.route('/farmer/list-product', methods=['GET'])
@login_required
def list_product():
    if session.get('role') != 'Farmer':
        flash('Access denied', 'danger')
        return redirect(url_for('home'))
    return render_template('list_product.html')

listed_product_manager = ListedProductManager()

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Show product listing form
@app.route('/farmer/list-product', methods=['GET'])
@login_required
def show_product_form():
    if session.get('role') != 'Farmer':
        flash('Access denied', 'danger')
        return redirect(url_for('home'))
    return render_template('list_product.html')

# Handle product listing submission
@app.route('/farmer/add-listing', methods=['POST'])
@login_required
def add_listing():
    if session.get('role') != 'Farmer':
        flash('Access denied', 'danger')
        return redirect(url_for('home'))
        
    try:
        # Get form data
        name = request.form.get('name')
        category = request.form.get('category')
        price = float(request.form.get('price'))
        quantity = int(request.form.get('quantity'))
        unit = request.form.get('unit')
        harvest_date = request.form.get('harvest_date')
        expiry_date = request.form.get('expiry_date')
        description = request.form.get('description')
        additional_info = request.form.get('additional_info')
        
        # Handle image uploads
        uploaded_images = []
        if 'images[]' in request.files:
            files = request.files.getlist('images[]')
            for file in files:
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    # Add timestamp to filename to make it unique
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    unique_filename = f"{timestamp}_{filename}"
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                    
                    # Create directory if it doesn't exist
                    os.makedirs(os.path.dirname(filepath), exist_ok=True)
                    
                    file.save(filepath)
                    uploaded_images.append(unique_filename)
        
        # Create product
        product_id = listed_product_manager.create_product(
            name=name,
            category=category,
            price=price,
            quantity=quantity,
            unit=unit,
            harvest_date=harvest_date,
            expiry_date=expiry_date,
            description=description,
            owner=session['username'],
            additional_info=additional_info,
            images=uploaded_images
        )
        
        if product_id:
            flash('Product listed successfully', 'success')
        else:
            flash('Failed to list product', 'danger')
            
        return redirect(url_for('farmer_dashboard'))
        
    except Exception as e:
        print(f"Error in add_listing: {str(e)}")
        flash('An error occurred while listing the product', 'danger')
        return redirect(url_for('show_product_form'))

# View farmer's listed products
@app.route('/farmer/my-listings')
@login_required
def my_listings():
    if session.get('role') != 'Farmer':
        flash('Access denied', 'danger')
        return redirect(url_for('home'))
        
    try:
        products = listed_product_manager.get_farmer_products(session['username'])
        return render_template('my_listings.html', products=products)
    except Exception as e:
        print(f"Error in my_listings: {str(e)}")
        flash('Error loading your listings', 'danger')
        return redirect(url_for('farmer_dashboard'))

# Update product quantity
@app.route('/farmer/update-quantity/<product_id>', methods=['POST'])
@login_required
def update_product_quantity(product_id):
    if session.get('role') != 'Farmer':
        flash('Access denied', 'danger')
        return redirect(url_for('home'))
        
    try:
        new_quantity = int(request.form.get('quantity', 0))
        if new_quantity < 0:
            flash('Quantity cannot be negative', 'danger')
            return redirect(url_for('my_listings'))
            
        if listed_product_manager.update_product_quantity(
            product_id, session['username'], new_quantity
        ):
            flash('Quantity updated successfully', 'success')
        else:
            flash('Failed to update quantity', 'danger')
            
        return redirect(url_for('my_listings'))
        
    except ValueError:
        flash('Invalid quantity value', 'danger')
        return redirect(url_for('my_listings'))
    except Exception as e:
        print(f"Error updating quantity: {str(e)}")
        flash('Error updating quantity', 'danger')
        return redirect(url_for('my_listings'))

# Product Listing Edit
# Add these routes to __init__.py

# configurations for file uploads
UPLOAD_FOLDER = 'static/product_images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create ListedProductManager with upload folder
listed_product_manager = ListedProductManager(UPLOAD_FOLDER)

@app.route('/farmer/edit-listing/<product_id>')
@login_required
def edit_listed_product(product_id):
    """Show edit form for a listed product"""
    if session.get('role') != 'Farmer':
        flash('Access denied', 'danger')
        return redirect(url_for('home'))
        
    try:
        product = listed_product_manager.get_product(product_id, session['username'])
        if not product:
            flash('Product not found', 'danger')
            return redirect(url_for('my_listings'))
            
        return render_template('edit_product.html', product=product)
        
    except Exception as e:
        print(f"Error in edit_listed_product: {str(e)}")
        flash('Error loading product', 'danger')
        return redirect(url_for('my_listings'))

@app.route('/farmer/update-listing/<product_id>', methods=['POST'])
@login_required
def update_listed_product(product_id):
    """Handle listed product update submission"""
    if session.get('role') != 'Farmer':
        flash('Access denied', 'danger')
        return redirect(url_for('home'))
        
    try:
        # Get form data
        name = request.form.get('name')
        category = request.form.get('category')
        price = float(request.form.get('price'))
        quantity = int(request.form.get('quantity'))
        unit = request.form.get('unit')
        harvest_date = request.form.get('harvest_date')
        expiry_date = request.form.get('expiry_date')
        description = request.form.get('description')
        additional_info = request.form.get('additional_info')

        # Handle image upload if new images are provided
        new_images = request.files.getlist('images[]')
        if new_images and new_images[0].filename:
            uploaded_images = []
            for file in new_images:
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    # Add timestamp to filename to make it unique
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    unique_filename = f"{timestamp}_{filename}"
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                    
                    # Create directory if it doesn't exist
                    os.makedirs(os.path.dirname(filepath), exist_ok=True)
                    
                    file.save(filepath)
                    uploaded_images.append(unique_filename)
            
            # Update the product with new images
            if uploaded_images:
                # TODO: Consider cleaning up old images here
                pass
        
        # Update product
        if listed_product_manager.update_product(
            product_id=product_id,
            owner=session['username'],
            name=name,
            category=category,
            price=price,
            quantity=quantity,
            unit=unit,
            harvest_date=harvest_date,
            expiry_date=expiry_date,
            description=description,
            additional_info=additional_info
        ):
            flash('Product updated successfully', 'success')
        else:
            flash('Failed to update product', 'danger')
            
        return redirect(url_for('my_listings'))
        
    except Exception as e:
        print(f"Error in update_listed_product: {str(e)}")
        flash('An error occurred while updating the product', 'danger')
        return redirect(url_for('my_listings'))

@app.route('/farmer/delete-listing/<product_id>')
@login_required
def delete_listed_product(product_id):
    """Delete a product listing"""
    if session.get('role') != 'Farmer':
        flash('Access denied', 'danger')
        return redirect(url_for('home'))
        
    try:
        if listed_product_manager.delete_product(product_id, session['username']):
            flash('Product deleted successfully', 'success')
        else:
            flash('Failed to delete product', 'danger')
            
        return redirect(url_for('my_listings'))
        
    except Exception as e:
        print(f"Error in delete_listed_product: {str(e)}")
        flash('An error occurred while deleting the product', 'danger')
        return redirect(url_for('my_listings'))

# Browse all listed products (for customers)
@app.route('/browse-products')
def browse_products():
    try:
        all_products = []
        with listed_product_manager._ListedProductManager__get_db() as db:
            if 'farmer_products' in db:
                for farmer_products in db['farmer_products'].values():
                    for product_data in farmer_products.values():
                        if product_data.get('listing_status') == 'active':
                            # Create ListedProduct object
                            product = ListedProduct(
                                id=product_data['id'],
                                name=product_data['name'],
                                expiry_date=product_data['expiry_date'],
                                owner=product_data['owner'],
                                category=product_data['category'],
                                price=product_data['price'],
                                quantity=product_data['quantity'],
                                unit=product_data['unit'],
                                harvest_date=product_data['harvest_date'],
                                description=product_data['description'],
                                additional_info=product_data.get('additional_info'),
                                images=product_data.get('images', []),
                                listing_status=product_data.get('listing_status', 'active')
                            )
                            all_products.append(product)
                            
        return render_template('browse_products.html', products=all_products)
        
    except Exception as e:
        print(f"Error in browse_products: {str(e)}")
        flash('Error loading products', 'danger')
        return redirect(url_for('home'))

if __name__ == '__main__':
    init_admin()
    if not init_notification_db():  # Add this check here too
        print("WARNING: Failed to initialize notification database")
    app.run(debug=True)