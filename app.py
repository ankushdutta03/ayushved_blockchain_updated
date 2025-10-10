import os
from flask import Flask, render_template, send_from_directory, redirect, url_for, request, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from datetime import datetime, timedelta
import qrcode, random, tempfile, re
from dotenv import load_dotenv

# Load .env variables
load_dotenv()

app = Flask(__name__)

# ---------------- MongoDB Config ----------------
MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    raise ValueError("Please set MONGO_URI in your .env file")

app.config["MONGO_URI"] = MONGO_URI
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'ayushved-secret-key-change-in-production')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Initialize Mongo
mongo = PyMongo(app)

# Test Mongo connection
try:
    mongo.cx.admin.command("ping")
    print("✅ MongoDB connected successfully!")
    print(f"🔗 Database: {mongo.db.name}")
except Exception as e:
    raise ConnectionError(f"❌ MongoDB connection failed: {e}")

# Database collections
users = mongo.db.users
herb_batches = mongo.db.herb_batches
otp_verifications = mongo.db.otp_verifications

# Upload directory configuration
UPLOAD_FOLDER = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Temporary OTP store (use Redis in production)
otp_store = {}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ---------------- Admin User ----------------
def create_admin_user():
    admin_user = users.find_one({"username": "admin"})
    if not admin_user:
        admin_user_data = {
            'full_name': 'Administrator',
            'username': 'admin',
            'password_hash': generate_password_hash('Vigilant@Voices'),
            'mobile_number': '9999999999',
            'email': 'admin@ayushved.com',
            'profile_photo': '',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow(),
            'is_admin': True
        }
        result = users.insert_one(admin_user_data)
        print("✅ Admin user created successfully!")
        print("👤 Username: admin")
        print("🔑 Password: Vigilant@Voices")
        print("📱 Mobile: 9999999999")
        print(f"🆔 User ID: {result.inserted_id}")
    else:
        print("ℹ️  Admin user already exists")

create_admin_user()

# ---------------- Auth Guard ----------------
from functools import wraps
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please login to access this page", "info")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

# ---------------- Utility Functions ----------------
def generate_otp():
    """Generate 6-digit OTP"""
    return str(random.randint(100000, 999999))

def validate_mobile(mobile):
    """Validate Indian mobile number"""
    pattern = r'^[6-9]\d{9}$'
    return bool(re.match(pattern, mobile))

def validate_email(email):
    """Basic email validation"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

# ---------------- Routes ----------------
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# ----------- Signup -----------
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        mobile_number = request.form.get('mobile_number', '').strip()

        # Enhanced validation
        if not all([full_name, username, password, confirm_password, mobile_number]):
            flash("All fields are required", "danger")
            return redirect(url_for('signup'))
        
        if len(full_name) < 2:
            flash("Full name must be at least 2 characters", "danger")
            return redirect(url_for('signup'))
        
        if len(username) < 3 or not re.match(r'^[a-zA-Z0-9_]+$', username):
            flash("Username must be 3+ characters (letters, numbers, underscore only)", "danger")
            return redirect(url_for('signup'))
        
        if password != confirm_password:
            flash("Passwords do not match", "danger")
            return redirect(url_for('signup'))
        
        if len(password) < 8:
            flash("Password must be at least 8 characters long", "danger")
            return redirect(url_for('signup'))
        
        if not validate_mobile(mobile_number):
            flash("Please enter a valid 10-digit mobile number", "danger")
            return redirect(url_for('signup'))
        
        # Check for existing users
        if users.find_one({"$or": [{"username": username}, {"mobile_number": mobile_number}]}):
            flash("Username or mobile number already exists", "danger")
            return redirect(url_for('signup'))

        # Create new user
        hashed_pw = generate_password_hash(password)
        new_user = {
            'full_name': full_name,
            'username': username,
            'password_hash': hashed_pw,
            'mobile_number': mobile_number,
            'email': '',
            'profile_photo': '',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow(),
            'is_admin': False
        }
        result = users.insert_one(new_user)
        
        # Auto login after signup
        session.clear()
        session['user_id'] = str(result.inserted_id)
        session['username'] = username
        
        flash("Account created successfully! Welcome to AyushVed! 🌱", "success")
        return redirect(url_for('dashboard'))
    
    return render_template('signup.html')

# ----------- Login -----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash("Username and password are required", "danger")
            return render_template('login.html')

        user = users.find_one({"username": username})
        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session['user_id'] = str(user['_id'])
            session['username'] = user['username']
            session['is_admin'] = user.get('is_admin', False)
            
            welcome_msg = f"Welcome back, {user['full_name']}! 🌿"
            if user.get('is_admin'):
                welcome_msg += " (Admin Access)"
            flash(welcome_msg, "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password", "danger")

    return render_template('login.html')

# ----------- Forgot Password -----------
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        mobile_number = request.form.get('mobile_number', '').strip()
        
        if not validate_mobile(mobile_number):
            flash("Please enter a valid mobile number", "danger")
            return render_template('forgot_password.html')
        
        user = users.find_one({"mobile_number": mobile_number})
        if not user:
            flash("No account found with this mobile number", "danger")
            return render_template('forgot_password.html')
        
        # Generate and store OTP
        otp = generate_otp()
        otp_store[mobile_number] = {
            'otp': otp,
            'expiry': datetime.utcnow() + timedelta(minutes=5)
        }
        
        # In production, send actual SMS here
        print(f"📱 OTP for {mobile_number}: {otp}")
        flash(f"OTP sent to {mobile_number} (Check console for demo)", "info")
        return redirect(url_for('verify_otp', mobile=mobile_number))
    
    return render_template('forgot_password.html')

# ----------- Verify OTP -----------
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    mobile = request.args.get('mobile') or request.form.get('mobile')
    
    if not mobile:
        flash("Invalid request", "danger")
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        otp = request.form.get('otp', '').strip()
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validate OTP
        if mobile not in otp_store:
            flash("OTP expired or invalid", "danger")
            return render_template('verify_otp.html', mobile=mobile)
        
        stored_otp_data = otp_store[mobile]
        if datetime.utcnow() > stored_otp_data['expiry']:
            del otp_store[mobile]
            flash("OTP has expired", "danger")
            return redirect(url_for('forgot_password'))
        
        if stored_otp_data['otp'] != otp:
            flash("Invalid OTP", "danger")
            return render_template('verify_otp.html', mobile=mobile)
        
        # Validate passwords
        if new_password != confirm_password:
            flash("Passwords do not match", "danger")
            return render_template('verify_otp.html', mobile=mobile)
        
        if len(new_password) < 8:
            flash("Password must be at least 8 characters", "danger")
            return render_template('verify_otp.html', mobile=mobile)
        
        # Update password in database
        result = users.update_one(
            {"mobile_number": mobile},
            {"$set": {
                "password_hash": generate_password_hash(new_password),
                "updated_at": datetime.utcnow()
            }}
        )
        
        if result.modified_count > 0:
            # Clear OTP and auto login
            del otp_store[mobile]
            user = users.find_one({"mobile_number": mobile})
            session.clear()
            session['user_id'] = str(user['_id'])
            session['username'] = user['username']
            
            flash("Password reset successfully! You are now logged in. 🔓", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Failed to reset password", "danger")
    
    return render_template('verify_otp.html', mobile=mobile)

# ----------- Logout -----------
@app.route('/logout')
def logout():
    username = session.get('username', 'User')
    session.clear()
    flash(f"Goodbye {username}! You've been logged out successfully. 👋", "info")
    return redirect(url_for('login'))

# ----------- Dashboard -----------
@app.route('/dashboard')
@login_required
def dashboard():
    user_batches = herb_batches.find({"user_id": session['user_id']}).sort("created_at", -1)
    user = users.find_one({"_id": ObjectId(session['user_id'])})
    
    # Statistics
    total_batches = herb_batches.count_documents({"user_id": session['user_id']})
    
    return render_template('dashboard.html', 
                         herb_batches=list(user_batches), 
                         user=user,
                         total_batches=total_batches)

# ----------- Add/Edit/Delete Batch -----------
@app.route('/add_batch', methods=['POST'])
@login_required
def add_batch():
    herb_name = request.form.get('herb_name', '').strip()
    collector = request.form.get('collector_name', '').strip()
    farm_location = request.form.get('farm_location', '').strip()
    notes = request.form.get('notes', '').strip()
    
    try:
        latitude = float(request.form.get('latitude', 0.0))
        longitude = float(request.form.get('longitude', 0.0))
    except ValueError:
        latitude = longitude = 0.0

    if not all([herb_name, collector, farm_location]):
        flash("Herb name, collector, and farm location are required", "danger")
        return redirect(url_for('dashboard'))

    # Get user info for created_by
    user = users.find_one({"_id": ObjectId(session['user_id'])})
    
    new_batch = {
        'herb_name': herb_name,
        'collector': collector,
        'farm_location': farm_location,
        'latitude': latitude,
        'longitude': longitude,
        'notes': notes,
        'user_id': session['user_id'],
        'created_by': user['full_name'],
        'created_at': datetime.utcnow(),
        'updated_at': datetime.utcnow()
    }
    
    result = herb_batches.insert_one(new_batch)
    flash(f"New herb batch '{herb_name}' added successfully! 🌱", "success")
    return redirect(url_for('dashboard'))

@app.route('/edit_batch/<batch_id>', methods=['GET', 'POST'])
@login_required
def edit_batch(batch_id):
    try:
        batch = herb_batches.find_one({"_id": ObjectId(batch_id)})
    except:
        flash("Invalid batch ID", "danger")
        return redirect(url_for('dashboard'))
    
    if not batch or batch['user_id'] != session['user_id']:
        flash("Batch not found or access denied", "danger")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        try:
            latitude = float(request.form.get('latitude', 0.0))
            longitude = float(request.form.get('longitude', 0.0))
        except ValueError:
            latitude = longitude = 0.0
            
        update_data = {
            'herb_name': request.form.get('herb_name', '').strip(),
            'collector': request.form.get('collector', '').strip(),
            'farm_location': request.form.get('farm_location', '').strip(),
            'notes': request.form.get('notes', '').strip(),
            'latitude': latitude,
            'longitude': longitude,
            'updated_at': datetime.utcnow()
        }
        
        herb_batches.update_one({"_id": ObjectId(batch_id)}, {"$set": update_data})
        flash("Batch updated successfully! ✏️", "success")
        return redirect(url_for('dashboard'))

    return render_template('edit_batch.html', batch=batch)

@app.route('/delete_batch/<batch_id>', methods=['POST'])
@login_required
def delete_batch(batch_id):
    try:
        batch = herb_batches.find_one({"_id": ObjectId(batch_id)})
    except:
        flash("Invalid batch ID", "danger")
        return redirect(url_for('dashboard'))
        
    if not batch or batch['user_id'] != session['user_id']:
        flash("Batch not found or access denied", "danger")
        return redirect(url_for('dashboard'))

    herb_batches.delete_one({"_id": ObjectId(batch_id)})
    flash(f"Batch '{batch['herb_name']}' deleted successfully 🗑️", "info")
    return redirect(url_for('dashboard'))

# ----------- Provenance & QR -----------
@app.route('/provenance/<batch_id>')
def provenance(batch_id):
    try:
        batch = herb_batches.find_one({"_id": ObjectId(batch_id)})
    except:
        flash("Invalid batch ID", "danger")
        return redirect(url_for('login'))
        
    if not batch:
        flash("Batch not found", "danger")
        return redirect(url_for('login'))
    return render_template('provenance.html', batch=batch)

@app.route('/generate_qr/<batch_id>')
@login_required
def generate_qr(batch_id):
    try:
        batch = herb_batches.find_one({"_id": ObjectId(batch_id)})
    except:
        flash("Invalid batch ID", "danger")
        return redirect(url_for('dashboard'))
        
    if not batch or batch['user_id'] != session['user_id']:
        flash("Batch not found or access denied", "danger")
        return redirect(url_for('dashboard'))

    url = url_for('provenance', batch_id=batch_id, _external=True)
    
    # Enhanced QR code with better settings
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(url)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    qr_filename = f'qr_batch_{batch_id}_{int(datetime.utcnow().timestamp())}.png'
    qr_path = os.path.join(tempfile.gettempdir(), qr_filename)
    img.save(qr_path)
    
    return send_from_directory(tempfile.gettempdir(), qr_filename, as_attachment=True)

# ----------- Scan QR -----------
@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    if request.method == 'POST':
        batch_id = request.form.get('batch_id', '').strip()
        
        if not batch_id:
            flash("Please enter a batch ID", "danger")
            return render_template('scan.html')
        
        try:
            batch = herb_batches.find_one({"_id": ObjectId(batch_id)})
            if batch:
                return redirect(url_for('provenance', batch_id=str(batch['_id'])))
            else:
                flash("Batch not found in database", "danger")
        except:
            flash("Invalid batch ID format", "danger")
    
    return render_template('scan.html')

# ----------- Profile -----------
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = users.find_one({"_id": ObjectId(session['user_id'])})
    if not user:
        flash("User not found", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        mobile_number = request.form.get('mobile_number', '').strip()
        current_password = request.form.get('current_password', '')

        # Basic validation
        if not full_name or not username or not mobile_number:
            flash("Full name, username, and mobile number are required", "danger")
            return redirect(url_for('profile'))
        
        if len(full_name) < 2:
            flash("Full name must be at least 2 characters", "danger")
            return redirect(url_for('profile'))
        
        if len(username) < 3 or not re.match(r'^[a-zA-Z0-9_]+$', username):
            flash("Username must be 3+ characters (letters, numbers, underscore only)", "danger")
            return redirect(url_for('profile'))
        
        if not validate_mobile(mobile_number):
            flash("Please enter a valid 10-digit mobile number", "danger")
            return redirect(url_for('profile'))
        
        if email and not validate_email(email):
            flash("Please enter a valid email address", "danger")
            return redirect(url_for('profile'))

        # Check for duplicate username/mobile
        existing_user = users.find_one({
            "$or": [{"username": username}, {"mobile_number": mobile_number}],
            "_id": {"$ne": ObjectId(session['user_id'])}
        })
        if existing_user:
            flash("Username or mobile number already used by another account", "danger")
            return redirect(url_for('profile'))

        update_data = {
            'full_name': full_name,
            'username': username,
            'email': email,
            'mobile_number': mobile_number,
            'updated_at': datetime.utcnow()
        }

        # Password change validation
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        
        if new_password or confirm_password:
            if not current_password:
                flash("Current password is required to change password", "danger")
                return redirect(url_for('profile'))
            
            if not check_password_hash(user['password_hash'], current_password):
                flash("Current password is incorrect", "danger")
                return redirect(url_for('profile'))
            
            if new_password != confirm_password:
                flash("New passwords do not match", "danger")
                return redirect(url_for('profile'))
            
            if len(new_password) < 8:
                flash("New password must be at least 8 characters", "danger")
                return redirect(url_for('profile'))
            
            update_data['password_hash'] = generate_password_hash(new_password)

        # Profile photo upload
        file = request.files.get('profile_photo')
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(f"user_{session['user_id']}_{int(datetime.utcnow().timestamp())}_{file.filename}")
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filepath)
            update_data['profile_photo'] = filename

        # Update user in database
        result = users.update_one({"_id": ObjectId(session['user_id'])}, {"$set": update_data})
        
        if result.modified_count > 0:
            # Update session username if changed
            session['username'] = username
            flash("Profile updated successfully! ✅", "success")
        else:
            flash("No changes were made", "info")
        
        return redirect(url_for('profile'))

    return render_template('profile.html', user=user)

# ----------- Admin Panel -----------
@app.route('/admin')
@login_required
def admin_panel():
    user = users.find_one({"_id": ObjectId(session['user_id'])})
    if not user or not user.get('is_admin'):
        flash("Admin access required", "danger")
        return redirect(url_for('dashboard'))

    all_users = list(users.find().sort("created_at", -1))
    all_batches = list(herb_batches.find().sort("created_at", -1))
    
    # Statistics
    total_users = len(all_users)
    total_batches = len(all_batches)
    
    return render_template('admin.html', 
                         users=all_users, 
                         batches=all_batches,
                         total_users=total_users,
                         total_batches=total_batches)

# ----------- API Routes (for AJAX) -----------
@app.route('/api/resend_otp', methods=['POST'])
def api_resend_otp():
    mobile = request.form.get('mobile')
    if not mobile or not validate_mobile(mobile):
        return jsonify({'success': False, 'message': 'Invalid mobile number'})
    
    user = users.find_one({"mobile_number": mobile})
    if not user:
        return jsonify({'success': False, 'message': 'User not found'})
    
    # Generate new OTP
    otp = generate_otp()
    otp_store[mobile] = {
        'otp': otp,
        'expiry': datetime.utcnow() + timedelta(minutes=5)
    }
    
    # In production, send actual SMS here
    print(f"📱 New OTP for {mobile}: {otp}")
    return jsonify({'success': True, 'message': 'OTP sent successfully'})

# ----------- Static Files -----------
@app.route('/static/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

# ----------- Error Handlers -----------
@app.errorhandler(404)
def not_found(error):
    flash("Page not found 🔍", "info")
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.errorhandler(500)
def internal_error(error):
    flash("An internal error occurred. Please try again. ⚠️", "danger")
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.errorhandler(413)
def too_large(error):
    flash("File too large. Please upload a smaller file (max 16MB). 📁", "danger")
    return redirect(url_for('profile'))

# ----------- Context Processors -----------
@app.context_processor
def inject_user():
    if 'user_id' in session:
        user = users.find_one({"_id": ObjectId(session['user_id'])})
        return dict(current_user=user)
    return dict(current_user=None)

# ---------------- Run App ----------------
if __name__ == '__main__':
    print("🚀 Starting AyushVed Flask Application...")
    print("🌿 Ayurvedic Herbs Traceability System")
    print("📊 MongoDB Integration Active")
    print("🔐 Environment Variables Loaded")
    print("=" * 50)
    
    # Get configuration from environment
    debug_mode = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
    host = os.getenv('FLASK_HOST', '127.0.0.1')
    port = int(os.getenv('FLASK_PORT', 5000))
    
    app.run(debug=debug_mode, host=host, port=port)
