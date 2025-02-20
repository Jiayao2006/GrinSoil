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
import google.generativeai as genai
import shutil
import uuid
import logging
import traceback
from flask_mail import Mail, Message

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# configurations for file uploads
UPLOAD_FOLDER = 'static/product_images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Configure Gemini API
GOOGLE_API_KEY = 'AIzaSyCCHGtN-tvTeawFeQj7q7t72-lsv_qlw18'  # Replace with your actual API key
genai.configure(api_key=GOOGLE_API_KEY)

# Initialize the model
model = genai.GenerativeModel('gemini-pro')

# Email configuration
# app.config['MAIL_SERVER'] = 'smtp.gmail.com'
# app.config['MAIL_PORT'] = 587
# app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USERNAME'] = 'grinsoil05@gmail.com'  # Use environment variables for security
# app.config['MAIL_PASSWORD'] = 'ycld ynid hhri xvhl'     # Use app password for Gmail
# app.config['MAIL_DEFAULT_SENDER'] = ('GrinSOIL Verification', 'grinsoil05@gmail.com')

# # Update these settings in __init__.py
# app.config['MAIL_SERVER'] = 'smtp.gmail.com'
# app.config['MAIL_PORT'] = 587
# app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USERNAME'] = 'grinsoil05@gmail.com'
# app.config['MAIL_DEFAULT_SENDER'] = 'grinsoil05@gmail.com'
# app.config['MAIL_PASSWORD'] = 'mmqf njws bhcj ffsf'  # We'll generate this




# Email configuration with environment variables for security
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.getenv('MAIL_USERNAME', 'grinsoil05@gmail.com'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD', 'mmqf njws bhcj ffsf'),  # Replace with your app password
    MAIL_DEFAULT_SENDER=('GrinSOIL', 'grinsoil05@gmail.com'),
    MAIL_MAX_EMAILS=None,
    MAIL_ASCII_ATTACHMENTS=False,
    MAIL_SUPPRESS_SEND=False,
    MAIL_DEBUG=True  # Set to False in production
)

# Initialize Flask-Mail
mail = Mail(app)

# Add error handling for mail sending
def send_email_with_retry(msg, max_retries=3):
    """Send email with retry mechanism"""
    for attempt in range(max_retries):
        try:
            mail.send(msg)
            return True
        except Exception as e:
            print(f"Attempt {attempt + 1} failed: {str(e)}")
            if attempt == max_retries - 1:
                print("All retry attempts failed")
                raise
            continue


# In your __init__.py
@app.before_request
def before_request():
    print(f"Before request session: {session}")  # Debug print

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
        email = data.get('email')
        
        if not email:
            return jsonify({
                'status': 'error', 
                'message': 'Email is required'
            }), 400

        # Validate email format on server-side
        import re
        email_regex = re.compile(r'^[^\s@]+@[^\s@]+\.[a-zA-Z]{2,}$')
        if not email_regex.match(email):
            return jsonify({
                'status': 'error', 
                'message': 'Invalid email format'
            }), 400

        # Generate OTP
        otp = otp_manager.generate_otp()
        
        # Additional email domain validation (optional)
        domain = email.split('@')[-1]
        allowed_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'mymail.nyp.edu.sg']
        if domain not in allowed_domains:
            return jsonify({
                'status': 'error', 
                'message': f'Email domain {domain} is not supported'
            }), 400

        # Create email message
        msg = Message(
            subject="GrinSOIL Email Verification",
            recipients=[email],
            html=f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #198754;">GrinSOIL Email Verification</h2>
                <p>Your verification code is:</p>
                <div style="background-color: #f8f9fa; padding: 15px; text-align: center; font-size: 24px; letter-spacing: 5px; font-family: monospace;">
                    {otp}
                </div>
                <p>This code will expire in 3 minutes.</p>
                <p style="color: #666; font-size: 14px;">If you didn't request this code, please ignore this email.</p>
            </div>
            """
        )
        
        # Store OTP first to ensure valid request
        otp_manager.store_otp(email, otp)
        
        # Send email with retry mechanism
        try:
            send_email_with_retry(msg)
            return jsonify({
                'status': 'success',
                'message': 'Verification code sent to your email',
                'expiresIn': 180  # 3 minutes in seconds
            })
        except Exception as smtp_error:
            print(f"SMTP Error: {str(smtp_error)}")
            # Remove stored OTP if email sending fails
            otp_manager.delete_otp(email)
            return jsonify({
                'status': 'error',
                'message': 'Failed to send verification email. Please try again.'
            }), 500
            
    except Exception as e:
        print(f"Error in send-otp: {str(e)}")
        return jsonify({
            'status': 'error', 
            'message': 'An unexpected error occurred'
        }), 500
    
@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    try:
        data = request.get_json()
        phone = data.get('phone')
        email = data.get('email')
        otp = data.get('otp')
        
        # Determine which identifier to use
        identifier = email if email else phone
        
        if not identifier or not otp:
            return jsonify({'error': 'Identifier and OTP are required'}), 400
        
        # Verify OTP
        is_valid, message = otp_manager.verify_otp(identifier, otp)
        
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
        print(f"Checking login - Current session: {session}")  # Debug print
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
        verified_email = request.form.get('verified_email')  # Get verified email
        full_phone = request.form.get('full_phone')  # Now optional
        role = request.form.get('role')
        
        # Debug prints
        print("Form Data Received:")
        print(f"Username: {username}")
        print(f"Email: {verified_email}")
        print(f"Phone: {full_phone}")
        print(f"Role: {role}")
        
        # Input validation
        if not username:
            flash('Username is required', 'danger')
            return redirect(url_for('signup_login'))
        
        if not password:
            flash('Password is required', 'danger')
            return redirect(url_for('signup_login'))
        
        if not verified_email:
            flash('Verified email is required', 'danger')
            return redirect(url_for('signup_login'))
            
        if not role:
            flash('Role selection is required', 'danger')
            return redirect(url_for('signup_login'))
        
        # Verify that email was verified with OTP
        if not otp_manager.is_verified(verified_email):
            flash('Email must be verified with OTP', 'danger')
            return redirect(url_for('signup_login'))
        
        # Validate password
        is_valid_password, password_message = validate_password(password)
        if not is_valid_password:
            flash(password_message, 'danger')
            return redirect(url_for('signup_login'))
        
        # Create user
        if user_manager.create_user(username, password, full_phone or '', role, verified_email):
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
    try:
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
            print(f"Login successful - Username: {username}, Role: {user.role}")  # Debug print
            
            flash('Login successful!', 'success')
            
            # Redirect based on role
            if user.role == 'Farmer':
                return redirect(url_for('farmer_dashboard'))
            elif user.role == 'Customer':
                return redirect(url_for('customer_dashboard'))
            else:
                flash('Invalid user role', 'danger')
                session.clear()
                return redirect(url_for('signup_login'))
            
        flash('Invalid username or password', 'danger')
        return redirect(url_for('signup_login'))
        
    except Exception as e:
        print(f"Error in login: {str(e)}")
        flash('An error occurred during login', 'danger')
        return redirect(url_for('signup_login'))

"""Logout route"""
@app.route('/logout')
def logout():
    # Clear the session
    session.clear()
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('home'))

"""farmer and customer dashboard"""
from dashboard_utils import (
    get_dashboard_stats,
    get_quick_actions,
    validate_dashboard_access,
    format_dashboard_data
)

@app.route('/farmer_dashboard')
@login_required
def farmer_dashboard():
    try:
        username = session['username']
        user = user_manager.get_user(username)
        
        if user.role != 'Farmer':
            flash('Access denied', 'danger')
            return redirect(url_for('home'))
        
        # Get notifications with proper filtering
        notification_counts = notification_manager.get_notification_counts('Farmer', username)
        recent_notifications = notification_manager.get_recent_notifications('Farmer', username, limit=5)
        
        # Get other dashboard data
        product_counts = product_manager.get_status_counts(username)
        
        # Get review count
        review_count = review_manager.get_user_review_count(username)
        
        return render_template(
            'farmer_dashboard.html',
            user=user,
            product_counts=product_counts,
            notification_counts=notification_counts,
            notifications=recent_notifications,
            review_count=review_count
        )
        
    except Exception as e:
        print(f"Error in farmer_dashboard: {str(e)}")
        import traceback
        traceback.print_exc()
        flash('Error loading dashboard', 'danger')
        return redirect(url_for('home'))


@app.route('/customer_dashboard')
@login_required
def customer_dashboard():
    """Customer dashboard route with improved error handling and recent products"""
    try:
        # Basic checks first
        print("Starting customer dashboard load...")
        print(f"Session data: {session}")
        
        if 'username' not in session:
            print("No username in session")
            flash('Please log in first', 'danger')
            return redirect(url_for('signup_login'))
            
        username = session.get('username')
        print(f"Loading dashboard for user: {username}")
        
        # Get user data with explicit error handling
        try:
            user = user_manager.get_user(username)
            if not user:
                print(f"User not found: {username}")
                session.clear()
                flash('User account not found', 'danger')
                return redirect(url_for('signup_login'))
        except Exception as e:
            print(f"Error getting user data: {str(e)}")
            flash('Error loading user data', 'danger')
            return redirect(url_for('home'))
            
        # Get product stats
        try:
            product_counts = product_manager.get_status_counts(username)
        except Exception as e:
            print(f"Error getting product counts: {str(e)}")
            product_counts = {'fresh': 0, 'expiring-soon': 0}
            
        # Get recent listed products (fetch 5 most recent products)
        try:
            listed_product_manager = ListedProductManager()
            
            # Get all listed products and sort by created date
            all_products = []
            with listed_product_manager._ListedProductManager__get_db() as db:
                if 'farmer_products' in db:
                    for farmer_products in db['farmer_products'].values():
                        for product_data in farmer_products.values():
                            if product_data.get('listing_status') == 'active' and product_data.get('quantity', 0) > 0:
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
                                    images=product_data.get('images', [])
                                )
                                all_products.append(product)
            
            # Sort products by created date (most recent first)
            all_products.sort(
                key=lambda x: datetime.strptime(x.created_at, "%Y-%m-%d %H:%M:%S"), 
                reverse=True
            )
            
            # Take top 5 recent products
            recent_products = all_products[:5]
            
        except Exception as e:
            print(f"Error getting recent products: {str(e)}")
            recent_products = []
        
        # Get notifications
        try:
            notifications = notification_manager.get_recent_notifications(
                'Customer', 
                username, 
                limit=5
            )
            notification_counts = notification_manager.get_notification_counts(
                'Customer', 
                username
            )
        except Exception as e:
            print(f"Error getting notifications: {str(e)}")
            notifications = []
            notification_counts = {'total': 0, 'unread': 0}
            
        # Get cart data
        try:
            cart = cart_manager.get_cart(username)
        except Exception as e:
            print(f"Error getting cart: {str(e)}")
            cart = None
            
        # Get review count
        try:
            review_count = review_manager.get_user_review_count(username)
        except Exception as e:
            print(f"Error getting review count: {str(e)}")
            review_count = 0
            
        print("Successfully gathered all dashboard data")
        
        return render_template(
            'customer_dashboard.html',
            user=user,
            product_counts=product_counts,
            notification_counts=notification_counts,
            notifications=notifications,
            cart=cart,
            review_count=review_count,
            recent_products=recent_products  # Add this new parameter
        )
        
    except Exception as e:
        print(f"Critical error in customer_dashboard: {str(e)}")
        import traceback
        traceback.print_exc()
        flash('An error occurred while loading the dashboard', 'danger')
        return redirect(url_for('home'))
    
# Add a debug route to check session and database state
@app.route('/debug/dashboard')
def debug_dashboard():
    """Debug route to check dashboard dependencies"""
    if not app.debug:
        return "Debug route only available in debug mode", 403
        
    try:
        debug_info = {
            'session': dict(session),
            'user_exists': bool(user_manager.get_user(session.get('username'))) if 'username' in session else False,
            'notifications_db_test': bool(notification_manager.get_notifications_for_role(session.get('role'))) if 'role' in session else False,
            'product_manager_test': bool(product_manager.get_status_counts(session.get('username'))) if 'username' in session else False
        }
        return jsonify(debug_info)
    except Exception as e:
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

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
    try:
        # Get user role before deletion
        user = user_manager.get_user(username)
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('admin_dashboard'))
            
        # Delete user data first
        if not user_manager.delete_user_data(username, user.role):
            flash('Error deleting user data', 'danger')
            return redirect(url_for('admin_dashboard'))
        
        # Then delete the user account
        if user_manager.delete_user(username):
            flash(f'User {username} has been deleted', 'success')
        else:
            flash('Error deleting user account', 'danger')
            
        return redirect(url_for('admin_dashboard'))
        
    except Exception as e:
        print(f"Error in admin delete_user: {str(e)}")
        import traceback
        traceback.print_exc()
        flash('An error occurred while deleting the user', 'danger')
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
    """Delete user account and all associated data"""
    try:
        username = session['username']
        role = session.get('role')
        
        # First delete all associated data
        if not user_manager.delete_user_data(username, role):
            flash('Error deleting user data', 'danger')
            return redirect(url_for('user_settings'))
        
        # Then delete the user account
        if user_manager.delete_user(username):
            session.clear()
            flash('Your account has been deleted successfully', 'success')
            return redirect(url_for('home'))
            
        flash('Failed to delete account', 'danger')
        return redirect(url_for('user_settings'))
        
    except Exception as e:
        print(f"Error in delete_user_account: {str(e)}")
        import traceback
        traceback.print_exc()
        flash('An error occurred while deleting your account', 'danger')
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
        username = session.get('username')
        print(f"Getting notifications for role: {user_role}")
        
        # Debug: Print database contents
        with shelve.open('notifications_db', 'r') as db:
            print("Database keys:", list(db.keys()))
            for key in db:
                print(f"Notification {key}:", db[key])
        
        notifications = notification_manager.get_notifications_for_role(
            user_role, 
            username=username if user_role == 'Farmer' else None
        )
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

@app.route('/notification/delete/<notification_id>', methods=['POST'])
@login_required
def delete_notification(notification_id):
    try:
        username = session['username']
        user_role = session.get('role')
        
        # Delete notification
        success = notification_manager.delete_notification(notification_id)
        
        if success:
            # Get updated notification counts after deletion
            notification_counts = notification_manager.get_notification_counts(user_role, username)
            
            return jsonify({
                'success': True,
                'message': 'Notification deleted successfully',
                'counts': notification_counts
            })
        
        return jsonify({
            'success': False,
            'message': 'Failed to delete notification'
        }), 400
        
    except Exception as e:
        print(f"Error in delete_notification: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'message': 'An error occurred while deleting the notification'
        }), 500


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
        print("Starting browse_products route")  # Debug print
        
        # Get filter parameters
        search = request.args.get('search', '').lower()
        category_filter = request.args.get('category', 'all')
        sort_by = request.args.get('sort', 'name')
        sort_order = request.args.get('order', 'asc')
        
        print(f"Filter params: search={search}, category={category_filter}, sort={sort_by}, order={sort_order}")  # Debug print

        all_products = []
        categories = set()  # To collect unique categories
        
        try:
            with listed_product_manager._ListedProductManager__get_db() as db:
                print("Opened database successfully")  # Debug print
                
                if 'farmer_products' not in db:
                    print("No farmer_products in database")  # Debug print
                    return render_template('browse_products.html', 
                                        products=[],
                                        categories=[],
                                        search=search,
                                        category_filter=category_filter,
                                        sort_by=sort_by,
                                        sort_order=sort_order)

                # Get all products
                for farmer_products in db.get('farmer_products', {}).values():
                    for product_data in farmer_products.values():
                        try:
                            if product_data.get('listing_status') == 'active':
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
                                    additional_info=product_data.get('additional_info', ''),
                                    images=product_data.get('images', [])
                                )
                                all_products.append(product)
                                categories.add(product.category)
                        except Exception as e:
                            print(f"Error processing product: {str(e)}")
                            continue

        except Exception as db_error:
            print(f"Database error: {str(db_error)}")
            raise

        print(f"Found {len(all_products)} products")  # Debug print

        # Apply filters
        filtered_products = all_products

        # Apply search filter
        if search:
            filtered_products = [p for p in filtered_products if 
                               search in p.name.lower() or 
                               search in p.description.lower() or
                               search in p.category.lower()]

        # Apply category filter
        if category_filter and category_filter != 'all':
            filtered_products = [p for p in filtered_products if p.category == category_filter]

        # Sort products
        try:
            reverse_order = sort_order == 'desc'
            if sort_by == 'name':
                filtered_products.sort(key=lambda x: x.name.lower(), reverse=reverse_order)
            elif sort_by == 'price':
                filtered_products.sort(key=lambda x: float(x.price), reverse=reverse_order)
            elif sort_by == 'date':
                filtered_products.sort(key=lambda x: datetime.strptime(x.harvest_date, "%Y-%m-%d"), 
                                    reverse=reverse_order)
        except Exception as sort_error:
            print(f"Error sorting products: {str(sort_error)}")
            # Continue with unsorted products rather than failing

        print(f"Returning {len(filtered_products)} filtered products")  # Debug print
        
        return render_template('browse_products.html',
                             products=filtered_products,
                             categories=sorted(categories),
                             search=search,
                             category_filter=category_filter,
                             sort_by=sort_by,
                             sort_order=sort_order)

    except Exception as e:
        print(f"Error in browse_products: {str(e)}")
        import traceback
        traceback.print_exc()
        flash('Error loading products', 'danger')
        return redirect(url_for('home'))
    
"""add to cart"""
cart_manager = CartManager()

@app.context_processor
def inject_cart():
    """Inject cart data into all templates"""
    try:
        if 'username' in session:
            cart = cart_manager.get_cart(session['username'])
            return {
                'cart': cart,
                'cart_items': cart.get_items(),
                'cart_total': cart.total,
                'cart_count': len(cart)
            }
        return {
            'cart': Cart(),
            'cart_items': [],
            'cart_total': 0,
            'cart_count': 0
        }
    except Exception as e:
        print(f"Error injecting cart: {str(e)}")
        return {
            'cart': Cart(),
            'cart_items': [],
            'cart_total': 0,
            'cart_count': 0
        }

@app.route('/shop')
@login_required
def shop():
    try:
        # Get filter parameters
        search = request.args.get('search', '').lower()
        category_filter = request.args.get('category', 'all')
        sort_by = request.args.get('sort', 'name')
        sort_order = request.args.get('order', 'asc')

        # Get all products
        all_products = []
        with listed_product_manager._ListedProductManager__get_db() as db:
            if 'farmer_products' in db:
                for farmer_products in db['farmer_products'].values():
                    for product_data in farmer_products.values():
                        if (product_data.get('listing_status') == 'active' and 
                            product_data.get('quantity', 0) > 0):
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
                                images=product_data.get('images', [])
                            )
                            all_products.append(product)

        # Apply search filter
        if search:
            all_products = [p for p in all_products if 
                          search in p.name.lower() or 
                          search in p.description.lower() or
                          search in p.category.lower()]

        # Apply category filter
        if category_filter != 'all':
            all_products = [p for p in all_products if p.category == category_filter]

        # Sort products
        reverse_order = sort_order == 'desc'
        if sort_by == 'name':
            all_products.sort(key=lambda x: x.name.lower(), reverse=reverse_order)
        elif sort_by == 'price':
            all_products.sort(key=lambda x: float(x.price), reverse=reverse_order)
        elif sort_by == 'date':
            all_products.sort(key=lambda x: datetime.strptime(x.created_at, "%Y-%m-%d %H:%M:%S"), 
                            reverse=reverse_order)

        # Get unique categories for filter dropdown
        categories = sorted(set(p.category for p in all_products))

        return render_template('shop.html', 
                             products=all_products,
                             categories=categories,
                             search=search,
                             category_filter=category_filter,
                             sort_by=sort_by,
                             sort_order=sort_order)

    except Exception as e:
        print(f"Error in shop: {str(e)}")
        flash('Error loading products', 'danger')
        return redirect(url_for('customer_dashboard'))

@app.route('/cart')
@login_required
def view_cart():
    """View shopping cart contents"""
    try:
        cart = cart_manager.get_cart(session['username'])
        return render_template('cart.html', cart=cart)
    except Exception as e:
        print(f"Error viewing cart: {str(e)}")
        flash('Error loading cart', 'danger')
        return redirect(url_for('shop'))

@app.route('/cart/add', methods=['POST'])
@login_required
def add_to_cart():
    """Add item to cart"""
    try:
        data = request.get_json()
        product_id = data.get('product_id')
        quantity = int(data.get('quantity', 1))

        # Get product details
        product = None
        with listed_product_manager._ListedProductManager__get_db() as db:
            for farmer_products in db.get('farmer_products', {}).values():
                if product_id in farmer_products:
                    product_data = farmer_products[product_id]
                    if product_data['quantity'] >= quantity:
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
                            description=product_data['description']
                        )
                    break

        if not product:
            return jsonify({'error': 'Product not found or insufficient stock'}), 400

        # Update cart
        cart = cart_manager.get_cart(session['username'])
        cart.add_item(product_id, quantity, product.name, product.price, product.unit)
        cart_manager.update_cart(session['username'], cart)

        return jsonify(cart.to_dict())

    except Exception as e:
        print(f"Error adding to cart: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Failed to add item to cart'}), 500

@app.route('/cart/update', methods=['POST'])
@login_required
def update_cart():
    try:
        data = request.get_json()
        product_id = data.get('product_id')
        quantity = int(data.get('quantity', 0))

        # Get product to check available quantity
        product = listed_product_manager.get_product(product_id)
        if not product:
            return jsonify({'error': 'Product not found'}), 404

        # Validate quantity
        if quantity > product.quantity:
            return jsonify({'error': f'Only {product.quantity} items available'}), 400
        if quantity < 1:
            return jsonify({'error': 'Quantity must be at least 1'}), 400

        # Update cart
        cart = cart_manager.get_cart(session['username'])
        cart.update_quantity(product_id, quantity)
        cart_manager.update_cart(session['username'], cart)

        return jsonify(cart.to_dict())

    except Exception as e:
        print(f"Error updating cart: {str(e)}")
        return jsonify({'error': 'Failed to update cart'}), 500

@app.route('/cart/remove', methods=['POST'])
@login_required
def remove_from_cart():
    """Remove item from cart"""
    try:
        data = request.get_json()
        product_id = data.get('product_id')

        cart = cart_manager.get_cart(session['username'])
        cart.remove_item(product_id)
        cart_manager.update_cart(session['username'], cart)

        return jsonify(cart.to_dict())

    except Exception as e:
        print(f"Error removing from cart: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Failed to remove item from cart'}), 500
    
@app.route('/chat/message', methods=['POST'])
def chat_message():
    try:
        data = request.get_json()
        user_message = data.get('message', '').lower().strip()
        
        if not user_message:
            return jsonify({'error': 'Message is required'}), 400

        # Get user context if logged in
        username = session.get('username')
        user_role = session.get('role')
        # Handle account-specific queries first
        if username and user_role:
            if any(keyword in user_message for keyword in ['order', 'orders', 'purchase', 'delivery']):
                order_history = _get_order_history(username, user_role)
                return jsonify({'response': order_history})
        
        # Define account-related keywords
        account_keywords = {
            'order': ['order', 'purchase', 'bought', 'buy'],
            'notification': ['notification', 'alert', 'message'],
            'cart': ['cart', 'basket', 'shopping'],
            'expiry': ['expiry', 'expire', 'expired', 'fresh'],
            'review': ['review', 'rating', 'feedback'],
            'profile': ['profile', 'account', 'settings'],
            'dashboard': ['dashboard', 'overview', 'summary']
        }
        
        # Check if query is account-related
        is_account_query = any(
            keyword in user_message 
            for keywords in account_keywords.values() 
            for keyword in keywords
        )
        
        # Handle account-related queries if user is logged in
        if is_account_query and username:
            # Extract context based on query type
            context = None
            
            # Context extraction function remains the same
            def extract_context(user_message):
                extractors = {
                    'expiry': lambda: _get_expiry_tracker_items(username),
                    'notification': lambda: _get_notifications(username, user_role),
                    'cart': lambda: _get_cart_items(username),
                    'order': lambda: _get_order_history(username, user_role),
                    'dashboard': lambda: _get_dashboard_overview(username, user_role),
                    'review': lambda: _get_user_reviews(username)
                }
                
                for category, keywords in account_keywords.items():
                    if any(keyword in user_message for keyword in keywords):
                        return extractors.get(category, lambda: None)()
                return None
            
            # Get account-specific context
            context = extract_context(user_message)
            
            if context:
                return jsonify({'response': context})
        
        # If not account-related or user not logged in, use Gemini for general queries
        context_prompt = """You are an AI assistant specialized in food and agriculture. 
        Respond to queries about:
        - Agricultural practices and crop cultivation
        - Food production and nutrition
        - Sustainable farming methods
        - Food science and safety
        - Plant biology and growth
        - Agricultural technology and innovation
        - Food storage and preservation
        - Cooking techniques and tips
        - Ingredient substitutions
        - Food pairing suggestions
        - Seasonal cooking
        - Traditional and modern cooking methods
        
        If the user is logged in, also provide personalized suggestions related to:
        - Food expiry tracking
        - Shopping for fresh produce
        - Managing food inventory
        - Sustainable consumption practices
        
        Keep responses concise, clear, and scientifically accurate.
        If a query is outside these domains, politely redirect to food and agriculture topics."""
        
        # Add user context to prompt if available
        if username:
            context_prompt += f"\n\nUser Context: {user_role} user"
        
        # Generate response using Gemini
        full_prompt = f"{context_prompt}\n\nUser Query: {user_message}"
        try:
            response = model.generate_content(full_prompt)
            if not response or not response.text:
                return jsonify({
                    'response': "I'm having trouble understanding. Could you rephrase your question?"
                })
            return jsonify({'response': response.text.strip()})
            
        except Exception as api_error:
            print(f"Gemini API Error: {str(api_error)}")
            return jsonify({
                'response': "I'm experiencing technical difficulties. Please try again."
            })
            
    except Exception as e:
        print(f"Error in chat_message: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Failed to process your request'}), 500

# Helper functions for context extraction
def _get_expiry_tracker_items(username):
    products = product_manager.get_user_products(username)
    if not products:
        return "You have no items in your expiry tracker. Would you like to learn how to start tracking your food expiry dates?"
    
    items_summary = "\n".join([
        f"- {p.name} (Expires: {p.expiry_date}, Status: {p.status})" 
        for p in products
    ])
    return f"Your Expiry Tracker Items:\n{items_summary}"

def _get_notifications(username, user_role):
    notifications = notification_manager.get_recent_notifications(user_role, username, limit=5)
    if not notifications:
        return "You have no recent notifications. I can help you understand how notifications work in our system."
    
    notif_summary = "\n".join([
        f"- {n.title}: {n.content[:50]}..." 
        for n in notifications
    ])
    return f"Recent Notifications:\n{notif_summary}"

def _get_cart_items(username):
    cart = cart_manager.get_cart(username)
    if not cart.items:
        return "Your cart is empty. Would you like to browse our available products?"
    
    cart_summary = "\n".join([
        f"- {item.name}: {item.quantity} {item.unit} at ${item.price} each" 
        for item in cart.get_items()
    ])
    return f"Your Cart Items:\n{cart_summary}\nTotal: ${cart.total:.2f}"

def _get_order_history(username, user_role):
    """
    Get detailed order history based on user role (Farmer or Customer)
    """
    try:
        with shelve.open('orders_db', 'r') as orders_db:
            all_orders = orders_db.get('orders', {})
            
            if user_role == 'Customer':
                # Get customer orders
                user_orders = []
                for order_id, order_data in all_orders.items():
                    if order_data.get('username') == username:
                        # Get farmer statuses for this order
                        farmer_statuses = order_data.get('farmer_statuses', {})
                        
                        # Determine overall order status
                        status_priority = {'Processing': 1, 'Completed': 2}
                        overall_status = max(
                            farmer_statuses.values(),
                            key=lambda s: status_priority.get(s, 0)
                        ) if farmer_statuses else 'Processing'
                        
                        formatted_order = {
                            'order_id': order_id,
                            'created_at': order_data.get('created_at', 'N/A'),
                            'total': float(order_data.get('total', 0)),
                            'status': overall_status,
                            'items_count': len(order_data.get('items', [])),
                            'farmer_statuses': farmer_statuses
                        }
                        user_orders.append(formatted_order)
                
                if not user_orders:
                    return "You haven't placed any orders yet. Would you like to browse our available products?"
                
                # Sort by date, most recent first
                user_orders.sort(
                    key=lambda x: datetime.strptime(x['created_at'], "%Y-%m-%d %H:%M:%S"),
                    reverse=True
                )
                
                # Format response for customer
                recent_orders = user_orders[:3]  # Show 3 most recent orders
                order_summary = "\n".join([
                    f"📦 Order {order['order_id']}:\n"
                    f"   - Date: {order['created_at']}\n"
                    f"   - Items: {order['items_count']}\n"
                    f"   - Total: ${order['total']:.2f}\n"
                    f"   - Status: {order['status']}\n"
                    f"   - Farmer Status Updates:\n     " + 
                    "\n     ".join([f"{farmer}: {status}" 
                                  for farmer, status in order['farmer_statuses'].items()])
                    for order in recent_orders
                ])
                
                return f"Your Recent Orders:\n\n{order_summary}\n\nTotal Orders: {len(user_orders)}"
                
            elif user_role == 'Farmer':
                # Get farmer orders
                farmer_orders = []
                for order_id, order_data in all_orders.items():
                    farmer_statuses = order_data.get('farmer_statuses', {})
                    
                    # Check if this farmer is involved in the order
                    if username in farmer_statuses:
                        # Extract only this farmer's items
                        farmer_items = []
                        order_total = 0
                        
                        for item in order_data.get('items', []):
                            try:
                                product_id = item.get('product_id')
                                if product_id:
                                    product = listed_product_manager.get_product(product_id)
                                    if product and product.owner == username:
                                        farmer_items.append(item)
                                        order_total += float(item.get('subtotal', 0))
                            except Exception as e:
                                print(f"Error processing item in farmer orders: {str(e)}")
                                continue
                        
                        if farmer_items:  # Only include orders with items from this farmer
                            formatted_order = {
                                'order_id': order_id,
                                'created_at': order_data.get('created_at', 'N/A'),
                                'customer': order_data.get('username', 'Unknown'),
                                'items_count': len(farmer_items),
                                'total': order_total,
                                'status': farmer_statuses.get(username, 'Processing'),
                                'shipping_info': order_data.get('shipping_info', {})
                            }
                            farmer_orders.append(formatted_order)
                
                if not farmer_orders:
                    return "You don't have any orders to fulfill yet."
                
                # Sort by date, most recent first
                farmer_orders.sort(
                    key=lambda x: datetime.strptime(x['created_at'], "%Y-%m-%d %H:%M:%S"),
                    reverse=True
                )
                
                # Format response for farmer
                recent_orders = farmer_orders[:3]  # Show 3 most recent orders
                order_summary = "\n".join([
                    f"🚚 Order {order['order_id']}:\n"
                    f"   - Date: {order['created_at']}\n"
                    f"   - Customer: {order['customer']}\n"
                    f"   - Items to Fulfill: {order['items_count']}\n"
                    f"   - Total Value: ${order['total']:.2f}\n"
                    f"   - Status: {order['status']}\n"
                    f"   - Shipping: {order['shipping_info'].get('name', 'N/A')}, "
                    f"{order['shipping_info'].get('address', 'N/A')}"
                    for order in recent_orders
                ])
                
                return f"Your Orders to Fulfill:\n\n{order_summary}\n\nTotal Orders: {len(farmer_orders)}"
            
            else:
                return "Unable to retrieve orders. Please check your account status."
            
    except Exception as e:
        print(f"Error in _get_order_history: {str(e)}")
        import traceback
        traceback.print_exc()
        return "I encountered an error while retrieving your order information. Please try again later."

def _get_dashboard_overview(username, user_role):
    try:
        product_counts = product_manager.get_status_counts(username)
        notification_counts = notification_manager.get_notification_counts(user_role, username)
        
        overview = f"""Dashboard Overview:
- Fresh Products: {product_counts.get('fresh', 0)}
- Expiring Soon: {product_counts.get('expiring-soon', 0)}
- Expired Products: {product_counts.get('expired', 0)}
- Unread Notifications: {notification_counts.get('unread', 0)}"""
        
        if user_role == 'Farmer':
            # Add farmer-specific information
            listed_products = listed_product_manager.get_farmer_products(username)
            active_listings = sum(1 for p in listed_products if p.listing_status == 'active')
            overview += f"\n- Active Product Listings: {active_listings}"
            
        return overview
        
    except Exception as e:
        print(f"Error getting dashboard overview: {str(e)}")
        return "Unable to retrieve dashboard information at the moment."

def _get_user_reviews(username):
    reviews = review_manager.get_user_reviews(username)
    if not reviews:
        return "You haven't written any reviews yet. Would you like to share your experience?"
    
    review_summary = "\n".join([
        f"- {review.created_at}: {review.content[:100]}..." 
        for review in reviews[:3]
    ])
    return f"Your Recent Reviews:\n{review_summary}"

def get_account_information(username, user_role, message):
    """Retrieve account-specific information based on query"""
    # Orders query
    if any(keyword in message for keyword in ['order', 'purchase']):
        try:
            with shelve.open('orders_db', 'r') as orders_db:
                all_orders = orders_db.get('orders', {})
                user_orders = [order for order in all_orders.values() if order.get('username') == username]
                
                if not user_orders:
                    return "You have no orders in your history."
                
                # Summarize orders
                order_summary = f"You have {len(user_orders)} total orders:\n"
                for i, order in enumerate(user_orders[-3:], 1):  # Show last 3 orders
                    order_summary += f"\nOrder {i}:\n"
                    order_summary += f"Order ID: {order.get('order_id', 'N/A')}\n"
                    order_summary += f"Date: {order.get('created_at', 'N/A')}\n"
                    order_summary += f"Total: ${order.get('total', 0):.2f}\n"
                    order_summary += f"Status: {order.get('status', 'Unknown')}\n"
                
                return order_summary
        except Exception as e:
            print(f"Error retrieving orders: {str(e)}")
            return "Unable to retrieve order information."
    
    # Notifications query
    elif 'notification' in message:
        try:
            notification_manager = NotificationManager()
            notifications = notification_manager.get_notifications_for_role(user_role, username)
            
            if not notifications:
                return "You have no notifications."
            
            # Summarize notifications
            notification_summary = f"You have {len(notifications)} total notifications:\n"
            for i, notification in enumerate(notifications[:3], 1):  # Show last 3 notifications
                notification_summary += f"\nNotification {i}:\n"
                notification_summary += f"Title: {notification.title}\n"
                notification_summary += f"Content: {notification.content[:100]}...\n"
                notification_summary += f"Date: {notification.created_at}\n"
            
            return notification_summary
        except Exception as e:
            print(f"Error retrieving notifications: {str(e)}")
            return "Unable to retrieve notification information."
    
    # Product listings (for Farmers)
    elif user_role == 'Farmer' and any(keyword in message for keyword in ['product', 'listing']):
        try:
            listed_product_manager = ListedProductManager()
            products = listed_product_manager.get_farmer_products(username)
            
            if not products:
                return "You have no product listings."
            
            # Summarize product listings
            product_summary = f"You have {len(products)} product listings:\n"
            for i, product in enumerate(products[:3], 1):  # Show first 3 products
                product_summary += f"\nProduct {i}:\n"
                product_summary += f"Name: {product.name}\n"
                product_summary += f"Quantity: {product.quantity} {product.unit}\n"
                product_summary += f"Price: ${product.price}/{product.unit}\n"
                product_summary += f"Status: {product.listing_status}\n"
            
            return product_summary
        except Exception as e:
            print(f"Error retrieving product listings: {str(e)}")
            return "Unable to retrieve product listing information."
    
    # Reviews query
    elif 'review' in message:
        try:
            review_manager = ReviewManager()
            reviews = review_manager.get_user_reviews(username)
            
            if not reviews:
                return "You have no reviews."
            
            # Summarize reviews
            review_summary = f"You have {len(reviews)} reviews:\n"
            for i, review in enumerate(reviews[:3], 1):  # Show last 3 reviews
                review_summary += f"\nReview {i}:\n"
                review_summary += f"Content: {review.content[:100]}...\n"
                review_summary += f"Date: {review.created_at}\n"
            
            return review_summary
        except Exception as e:
            print(f"Error retrieving reviews: {str(e)}")
            return "Unable to retrieve review information."
    
    # General account information
    else:
        return f"""Account Information:
Username: {username}
Role: {user_role}

You can ask about:
- Orders
- Notifications
- Product Listings (Farmers)
- Reviews"""



    
"""checkout"""
@app.route('/checkout')
@login_required
def checkout():
    try:
        cart = cart_manager.get_cart(session['username'])
        return render_template('checkout.html', cart=cart)
    except Exception as e:
        print(f"Error in checkout: {str(e)}")
        flash('Error loading checkout page', 'danger')
        return redirect(url_for('view_cart'))
    
@app.route('/confirmation')
@login_required
def confirmation():
    try:
        # Get the latest order ID, first from session, then try to find a recent order
        order_id = session.get('latest_order_id')
        
        print("CONFIRMATION: DEBUG START")
        print(f"Order ID from session: {order_id}")
        print(f"Full session contents: {dict(session)}")
        
        # If no order ID in session, try to find the most recent order
        if not order_id:
            with shelve.open('orders_db', 'r') as db:
                print("CONFIRMATION: No order ID in session, checking database")
                if 'orders' in db:
                    # Find the most recent order for the user
                    recent_orders = [
                        (oid, order) for oid, order in db['orders'].items() 
                        if order.get('username') == session['username'] 
                        and order.get('status') in ['processing', 'completed']
                    ]
                    
                    print(f"CONFIRMATION: Found {len(recent_orders)} recent orders")
                    
                    if recent_orders:
                        # Sort by creation time and get the most recent
                        recent_orders.sort(
                            key=lambda x: datetime.strptime(x[1]['created_at'], "%Y-%m-%d %H:%M:%S"), 
                            reverse=True
                        )
                        order_id, order_data = recent_orders[0]
                        print(f"CONFIRMATION: Using recent order: {order_id}")
                    else:
                        print("CONFIRMATION: No recent orders found")
                        flash('No recent orders found', 'danger')
                        return redirect(url_for('shop'))
                else:
                    print("CONFIRMATION: No orders in database")
                    flash('No orders found', 'danger')
                    return redirect(url_for('shop'))
        else:
            # Retrieve order from database
            with shelve.open('orders_db', 'r') as db:
                if 'orders' not in db or order_id not in db['orders']:
                    print(f"CONFIRMATION: Order {order_id} not found in database")
                    flash('Order not found', 'danger')
                    return redirect(url_for('shop'))
                
                order_data = db['orders'][order_id]
        
        # Validate order belongs to current user
        if order_data['username'] != session['username']:
            print("CONFIRMATION: Unauthorized order access")
            flash('Unauthorized access to order', 'danger')
            return redirect(url_for('shop'))
        
        # Ensure order is processed or completed
        if order_data.get('status') not in ['processing', 'completed']:
            print("CONFIRMATION: Order not in processable state")
            flash('Order is not in a valid state', 'danger')
            return redirect(url_for('shop'))
        
        # Extensive debugging for order data
        print("CONFIRMATION: Full Order Data:")
        print(json.dumps(order_data, indent=2))
        
        print("CONFIRMATION: Order Items Type:", type(order_data.get('items')))
        print("CONFIRMATION: Order Items Content:", order_data.get('items'))
        
        # Convert datetime string to a more readable format
        order_data['created_at_formatted'] = datetime.strptime(
            order_data['created_at'], 
            "%Y-%m-%d %H:%M:%S"
        ).strftime("%B %d, %Y at %I:%M %p")
        
        # Clear session variables after processing
        session.pop('latest_order_id', None)
        
        return render_template('confirmation.html', order=order_data)
                
    except Exception as e:
        print(f"CONFIRMATION: Error processing confirmation: {str(e)}")
        import traceback
        traceback.print_exc()
        flash('Error processing order', 'danger')
        return redirect(url_for('shop'))
    
"""pdf"""
# Initialize PDF manager
order_manager = OrderManager()

@app.route('/order/create', methods=['POST'])
@login_required
def create_order():
    try:
        # Get shipping info from form
        shipping_info = {
            'name': request.form.get('fullName'),
            'phone': request.form.get('phone'),
            'address': request.form.get('street'),
            'city': request.form.get('city'),
            'postal_code': request.form.get('postalCode')
        }
        
        # Get cart data
        cart = cart_manager.get_cart(session['username'])
        
        # Create order
        order_id = order_manager.create_order(
            username=session['username'],
            cart_items=cart.items,
            shipping_info=shipping_info
        )
        
        if not order_id:
            raise Exception("Failed to create order")
        
        # Get the order data for PDF generation
        order_data = {
            'order_id': order_id,
            'items': [item.to_dict() for item in cart.items.values()],
            'total': cart.total,
            'shipping_info': shipping_info,
            'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Clear cart after successful order
        new_cart = Cart()
        cart_manager.update_cart(session['username'], new_cart)
        
        return jsonify({
            'status': 'success',
            'order_id': order_id,
            'order_data': order_data
        })
        
    except Exception as e:
        print(f"Error creating order: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to create order'
        }), 500

@app.route('/order/<order_id>')
@login_required
def get_order(order_id):
    try:
        order_data = order_manager.get_order(order_id)
        if not order_data or order_data['username'] != session['username']:
            return jsonify({
                'status': 'error',
                'message': 'Order not found'
            }), 404
            
        return jsonify({
            'status': 'success',
            'order_data': order_data
        })
        
    except Exception as e:
        print(f"Error getting order: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to get order'
        }), 500

@app.route('/checkout/complete', methods=['POST'])
@login_required
def complete_checkout():
    try:
        # Get shipping info from form
        shipping_info = {
            'name': request.form.get('fullName'),
            'phone': request.form.get('phone'),
            'address': request.form.get('street'),
            'city': request.form.get('city'),
            'postal_code': request.form.get('postalCode')
        }
        
        # Validate shipping info
        if not all(shipping_info.values()):
            print("CHECKOUT: Incomplete shipping information")
            flash('Please fill in all shipping information', 'danger')
            return redirect(url_for('checkout'))
        
        # Get cart
        cart = cart_manager.get_cart(session['username'])
        
        # Check if cart is empty
        if not cart.items:
            print("CHECKOUT: Cart is empty")
            flash('Your cart is empty', 'danger')
            return redirect(url_for('checkout'))
        
        # Debug: Print cart items
        print("CHECKOUT: Cart Items:")
        for pid, item in cart.items.items():
            print(f"Product ID: {pid}, Name: {item.name}, Quantity: {item.quantity}, Price: {item.price}")
        
        # Validate stock before creating order
        stock_check_passed = True
        insufficient_items = []
        
        for item in cart.items.values():
            product = listed_product_manager.get_product(item.product_id)
            
            if not product:
                print(f"CHECKOUT: Product not found - {item.name} (ID: {item.product_id})")
                stock_check_passed = False
                insufficient_items.append(item.name)
                continue
            
            print(f"CHECKOUT: Stock check - {item.name}")
            print(f"Requested Quantity: {item.quantity}, Available: {product.quantity}")
            
            if product.quantity < item.quantity:
                print(f"CHECKOUT: Insufficient stock for {item.name}")
                stock_check_passed = False
                insufficient_items.append(item.name)
        
        # Stop if stock check fails
        if not stock_check_passed:
            error_message = f"Insufficient stock for: {', '.join(insufficient_items)}"
            print(f"CHECKOUT: {error_message}")
            flash(error_message, 'danger')
            return redirect(url_for('checkout'))
        
        # After validating stock, determine farmers involved
        farmers = set()
        for item in cart.items.values():
            product = listed_product_manager.get_product(item.product_id)
            if product:
                farmers.add(product.owner)

        # Create a notification for each involved farmer
        for farmer_username in farmers:
            notification_manager.create_notification(
                title="New Order Received",
                content=f"Customer {session['username']} has purchased your product.",
                target_role='Farmer',
                target_user=farmer_username  # Target specific farmer
            )
        
        # Create order with initial processing status
        # Convert cart items to a format that can be easily stored and retrieved
        cart_items_for_order = [
            {
                'product_id': item.product_id,
                'name': item.name,
                'quantity': item.quantity,
                'price': item.price,
                'unit': item.unit,
                'subtotal': item.subtotal
            } for item in cart.items.values()
        ]
        # Debugging print to check cart items
        print("Cart Items Before Clearing:", cart.items)
        # Create order with initial processing status
        # Create order with farmer_statuses
        order_id = order_manager.create_order(
            username=session['username'],
            cart_items=cart_items_for_order,
            shipping_info=shipping_info,
            status=OrderStatus.PROCESSING,
            farmer_statuses={farmer: OrderStatus.PROCESSING for farmer in farmers}
        )
        
        # Debug: Check order creation
        print(f"CHECKOUT: Order created with ID {order_id}")
        
        # Store the cart items in the session before clearing
        session['last_order_items'] = {
            pid: item.to_dict() for pid, item in cart.items.items()
        }

        if not order_id:
            print("CHECKOUT: Failed to create order")
            flash('Failed to create order', 'danger')
            return redirect(url_for('checkout'))
        
        # Update product quantities and finalize order
        try:
            for item in cart.items.values():
                product = listed_product_manager.get_product(item.product_id)
                
                if product:
                    # Reduce stock
                    new_quantity = product.quantity - item.quantity
                    listed_product_manager.update_product_quantity(
                        item.product_id, 
                        product.owner, 
                        new_quantity
                    )
                    print(f"CHECKOUT: Updated stock for {item.name}. New quantity: {new_quantity}")
                else:
                    print(f"CHECKOUT: Product not found during stock update - {item.name}")
            
            # Mark order as completed
            if order_manager.finalize_order(order_id, cart_manager, session['username']):
                print(f"CHECKOUT: Order {order_id} finalized successfully")
                # Store order ID in session
                session['latest_order_id'] = order_id
                return redirect(url_for('confirmation'))
            else:
                print("CHECKOUT: Failed to finalize order")
                flash('Failed to complete order', 'danger')
                return redirect(url_for('checkout'))
                
        except Exception as e:
            print(f"CHECKOUT: Error finalizing order: {str(e)}")
            order_manager.update_order_status(order_id, OrderStatus.CANCELLED)
            flash('An error occurred while processing your order', 'danger')
            return redirect(url_for('checkout'))
        
    except Exception as e:
        print(f"CHECKOUT: Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        flash('An unexpected error occurred', 'danger')
        return redirect(url_for('checkout'))

@app.route('/order/latest')
@login_required
def get_latest_order():
    try:
        # Open the shelve database directly
        with shelve.open('orders_db') as db:
            if 'orders' in db:
                # Filter and sort orders for the current user
                user_orders = [
                    order for order in db['orders'].values() 
                    if order['username'] == session['username']
                ]
                
                if not user_orders:
                    return jsonify({'status': 'error', 'message': 'No orders found for this user'}), 404
                
                # Get the most recent order
                latest_order = max(user_orders, key=lambda x: datetime.strptime(x['created_at'], "%Y-%m-%d %H:%M:%S"))
                
                return jsonify({
                    'status': 'success',
                    'order_data': {
                        'order_id': latest_order['order_id'],
                        'items': latest_order['items'],
                        'total': sum(item['subtotal'] for item in latest_order['items']),
                        'shipping_info': latest_order['shipping_info'],
                        'date': latest_order['created_at']
                    }
                })
            
            return jsonify({'status': 'error', 'message': 'No orders found'}), 404
    
    except Exception as e:
        print(f"Error getting latest order: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': 'Failed to retrieve latest order'}), 500

"""farmers to view and update orders"""
@app.route('/farmer/orders')
@login_required
def farmer_orders():
    if session.get('role') != 'Farmer':
        flash('Access denied', 'danger')
        return redirect(url_for('home'))
    
    try:
        farmer_username = session['username']
        status_filter = request.args.get('status', 'all')
        orders = []
        
        # Open both databases
        with shelve.open('orders_db', 'r') as orders_db, \
             shelve.open('users_db', 'r') as users_db:
            
            # Get all orders
            all_orders = orders_db.get('orders', {})
            
            for order_id, order_data in all_orders.items():
                # Check if this order involves the farmer
                farmer_statuses = order_data.get('farmer_statuses', {})
                
                if farmer_username not in farmer_statuses:
                    continue
                
                # Extract items that belong to this farmer
                raw_items = order_data.get('items', [])
                farmer_products = []  # Renamed to avoid conflict with dict.items()
                
                for item in raw_items:
                    # Skip non-dict items
                    if not isinstance(item, dict):
                        continue
                    
                    # Attempt different methods to identify farmer's items
                    try:
                        # Method 1: Check by product ownership
                        product_id = item.get('product_id')
                        if product_id:
                            product = listed_product_manager.get_product(product_id)
                            if product and product.owner == farmer_username:
                                farmer_products.append(item)
                                continue
                        
                        # Method 2: Check by farmer_username field
                        if item.get('farmer_username') == farmer_username:
                            farmer_products.append(item)
                            continue
                        
                        # Method 3: If this farmer is the only one in the order, include all items
                        if len(farmer_statuses) == 1 and farmer_username in farmer_statuses:
                            farmer_products.append(item)
                    except Exception:
                        continue
                
                # Skip if no items for this farmer
                if not farmer_products:
                    continue
                
                # Prepare customer details
                customer_username = order_data.get('username', 'Unknown')
                customer_details = users_db.get(customer_username, {})
                shipping_info = order_data.get('shipping_info', {})
                
                # Create order object
                order = {
                    'order_id': order_id,
                    'order_products': farmer_products,  # Changed key name to avoid conflict
                    'status': farmer_statuses.get(farmer_username, 'Unknown'),
                    'customer': customer_username,
                    'customer_details': {
                        'full_name': shipping_info.get('name', customer_details.get('username', customer_username)),
                        'phone': shipping_info.get('phone', 'N/A'),
                        'address': ', '.join(filter(bool, [
                            shipping_info.get('street', ''),
                            shipping_info.get('city', ''),
                            shipping_info.get('postal_code', '')
                        ]))
                    },
                    'created_at': order_data.get('created_at', 'N/A'),
                    'total': sum(item.get('subtotal', 0) for item in farmer_products),
                }
                
                # Apply status filter
                if status_filter == 'all' or order['status'] == status_filter:
                    orders.append(order)
        
        return render_template('farmer_orders.html', 
                              orders=orders, 
                              status_filter=status_filter)
    
    except Exception as e:
        print(f"Error in farmer_orders: {str(e)}")
        import traceback
        traceback.print_exc()
        flash('Error loading orders', 'danger')
        return redirect(url_for('farmer_dashboard'))

@app.route('/farmer/update_order_status/<order_id>', methods=['POST'])
@login_required
def update_farmer_order_status(order_id):
    new_status = request.form.get('status')
    if new_status not in ['Processing', 'Completed']:
        flash('Invalid status', 'danger')
        return redirect(url_for('farmer_orders'))
    
    success = order_manager.update_farmer_order_status(
        order_id, 
        session['username'], 
        new_status
    )
    if success:
        flash('Status updated', 'success')
    else:
        flash('Update failed', 'danger')
    return redirect(url_for('farmer_orders'))


@app.route('/farmer/delete-order/<order_id>', methods=['POST'])
@login_required
def delete_farmer_order(order_id):
    """Handle order deletion with proper validation and error handling"""
    # Verify user is a farmer
    if session.get('role') != 'Farmer':
        flash('Access denied. Only farmers can delete orders.', 'danger')
        return redirect(url_for('home'))
    
    try:
        # Get username from session
        farmer_username = session['username']
        
        # Attempt to delete the order
        if order_manager.delete_order(order_id, farmer_username):
            flash('Order deleted successfully', 'success')
        else:
            flash('Failed to delete order. Please try again.', 'danger')
            
        return redirect(url_for('farmer_orders'))
        
    except Exception as e:
        print(f"Critical error in delete_farmer_order: {str(e)}")
        import traceback
        traceback.print_exc()
        flash('An error occurred while deleting the order', 'danger')
        return redirect(url_for('farmer_orders'))
    
"""order tracker"""
@app.route('/customer/order-tracker')
@login_required
def customer_order_tracker():
    """Show customer's order history with status filtering"""
    if session.get('role') != 'Customer':
        flash('Access denied', 'danger')
        return redirect(url_for('home'))
        
    try:
        username = session['username']
        status_filter = request.args.get('status', 'all').lower()
        orders = []
        unique_statuses = set()  # Collect unique farmer statuses
        
        # Open orders database and get all orders
        with shelve.open('orders_db', 'r') as orders_db:
            all_orders = orders_db.get('orders', {})
            
            # Filter orders for current user and format them
            for order_id, order_data in all_orders.items():
                if order_data.get('username') == username:
                    # Get farmer statuses for this order
                    farmer_statuses = order_data.get('farmer_statuses', {})
                    
                    # Collect unique statuses
                    unique_statuses.update(farmer_statuses.values())
                    
                    # Determine order-level filter
                    # Get maximum status (typically the most challenging status)
                    status_priority = {
                        'Processing': 1,
                        'Completed': 2
                    }
                    max_status = max(
                        farmer_statuses.values(), 
                        key=lambda s: status_priority.get(s, 0)
                    ) if farmer_statuses else 'Processing'
                    
                    # Apply status filter
                    if status_filter != 'all' and status_filter not in [s.lower() for s in farmer_statuses.values()]:
                        continue
                    
                    # Format the order data
                    formatted_order = {
                        'order_id': order_data.get('order_id', order_id),
                        'created_at': order_data.get('created_at', ''),
                        'items': list(order_data.get('items', [])),
                        'total': float(order_data.get('total', 0)),
                        'shipping_info': order_data.get('shipping_info', {
                            'name': '',
                            'phone': '',
                            'address': '',
                            'city': '',
                            'postal_code': ''
                        }),
                        'farmer_statuses': farmer_statuses,
                        'status': max_status
                    }
                    orders.append(formatted_order)
            
            # Sort orders by date, most recent first
            orders.sort(
                key=lambda x: datetime.strptime(x['created_at'], "%Y-%m-%d %H:%M:%S"),
                reverse=True
            )
        
        return render_template('customer_order_tracker.html', 
                             orders=orders,
                             status_filter=status_filter,
                             unique_statuses=list(unique_statuses))
        
    except Exception as e:
        print(f"Error in customer_order_tracker: {str(e)}")
        import traceback
        traceback.print_exc()
        flash('Error loading order history', 'danger')
        return redirect(url_for('customer_dashboard'))
    
@app.route('/terms')
def terms():
    return render_template('terms_of_service.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy_policy.html')
    
if __name__ == '__main__':
    init_admin()
    if not init_notification_db():  # Add this check here too
        print("WARNING: Failed to initialize notification database")
    app.run(debug=True)