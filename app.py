import os
from flask import Flask, render_template, send_from_directory, redirect, url_for, request, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from datetime import datetime
import qrcode, random, tempfile

app = Flask(__name__)

# MongoDB Configuration
if os.environ.get('MONGO_URI'):
    app.config["MONGO_URI"] = os.environ.get('MONGO_URI')
else:
    # Local development - you can install MongoDB locally or use a local connection string
    app.config["MONGO_URI"] = "mongodb://localhost:27017/ayutrace_dev"

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'supersecretkey')

mongo = PyMongo(app)

# Database collections
users = mongo.db.users
herb_batches = mongo.db.herb_batches

# Create uploads directory for profile photos
UPLOAD_DIR = os.path.join(tempfile.gettempdir(), 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

otp_store = {}  # Temporary OTP store

# Create admin user if it doesn't exist
def create_admin_user():
    admin_user = users.find_one({"username": "admin"})
    if not admin_user:
        admin_user_data = {
            'full_name': 'admin',
            'username': 'admin',
            'password_hash': generate_password_hash('Vigilant@Voices'),
            'mobile_number': '9999999999',
            'email': '',
            'profile_photo': '',
            'created_at': datetime.utcnow()
        }
        users.insert_one(admin_user_data)
        print("✅ Admin user created successfully!")
        print("Username: admin")
        print("Password: Vigilant@Voices")
        print("Mobile: 9999999999")

# Initialize admin user
create_admin_user()

# ---------- Debug Route ----------
@app.route('/debug_session')
def debug_session():
    """Debug route to check session data"""
    return f"""
    <h2>Session Debug Info</h2>
    <p><strong>Session Data:</strong> {dict(session)}</p>
    <p><strong>User ID:</strong> {session.get('user_id', 'Not set')}</p>
    <p><strong>Username:</strong> {session.get('username', 'Not set')}</p>
    <p><strong>Is logged in:</strong> {'Yes' if 'user_id' in session else 'No'}</p>
    <br>
    <a href="/dashboard">Go to Dashboard</a> | <a href="/login">Go to Login</a>
    """

# ---------- Auth Guard ----------
def login_required(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

# ---------- Home Route ----------
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# ---------- Auth Routes ----------
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        username = full_name.lower().replace(" ", "_")
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        mobile_number = request.form.get('mobile_number', '').strip()

        # Validation
        if not all([full_name, password, confirm_password, mobile_number]):
            flash("All fields are required", "danger")
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash("Passwords do not match", "danger")
            return redirect(url_for('signup'))

        if len(password) < 6:
            flash("Password must be at least 6 characters long", "danger")
            return redirect(url_for('signup'))

        if users.find_one({"username": username}):
            flash("Username already exists", "danger")
            return redirect(url_for('signup'))

        if users.find_one({"mobile_number": mobile_number}):
            flash("Mobile number already registered", "danger")
            return redirect(url_for('signup'))

        hashed_pw = generate_password_hash(password)
        new_user = {
            'full_name': full_name,
            'username': username,
            'password_hash': hashed_pw,
            'mobile_number': mobile_number,
            'email': '',
            'profile_photo': '',
            'created_at': datetime.utcnow()
        }
        users.insert_one(new_user)
        flash(f"Signup successful. Your username is '{username}'. Please login.", "success")
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        print(f"🔍 Login attempt - Username: '{username}'")  # Debug
        
        if not username or not password:
            flash("Username and password are required", "danger")
            return render_template('login.html')
        
        user = users.find_one({"username": username})
        print(f"🔍 User found in database: {user is not None}")  # Debug
        
        if user:
            print(f"🔍 User details - ID: {user['_id']}, Username: {user['username']}")  # Debug
            password_match = check_password_hash(user['password_hash'], password)
            print(f"🔍 Password match: {password_match}")  # Debug
            
            if password_match:
                # Clear any existing flash messages before login
                session.pop('_flashes', None)
                
                session['user_id'] = str(user['_id'])
                session['username'] = user['username']
                
                print(f"✅ Login successful! Session set - User ID: {session['user_id']}")  # Debug
                
                # Show admin welcome message for admin user
                if user['username'] == 'admin':
                    flash("Welcome back, Administrator! 🔧", "success")
                    print("🔧 Admin user logged in!")  # Debug
                else:
                    flash("Welcome back!", "success")
                
                return redirect(url_for('dashboard'))
            else:
                flash("Invalid password", "danger")
                print("❌ Password mismatch")  # Debug
        else:
            flash("Username not found", "danger")
            print("❌ Username not found in database")  # Debug
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    print(f"🔍 Logout - Current user: {session.get('username', 'None')}")  # Debug
    # Clear all session data including flash messages
    session.clear()
    flash("You have been logged out successfully", "info")
    return redirect(url_for('login'))

# ---------- Forgot Password ----------
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        mobile = request.form.get('mobile_number', '').strip()
        
        if not mobile:
            flash("Mobile number is required", "danger")
            return redirect(url_for('forgot_password'))
        
        user = users.find_one({"mobile_number": mobile})
        if not user:
            flash("Mobile number not found in our records", "danger")
            return redirect(url_for('forgot_password'))

        otp = str(random.randint(100000, 999999))
        otp_store[mobile] = otp
        flash(f"OTP sent to {mobile} (Demo: {otp})", "info")
        return render_template('verify_otp.html', mobile=mobile)

    return render_template('forgot_password.html')

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    mobile = request.form.get('mobile', '').strip()
    entered_otp = request.form.get('otp', '').strip()
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')

    if not all([mobile, entered_otp, new_password, confirm_password]):
        flash("All fields are required", "danger")
        return redirect(url_for('forgot_password'))

    if entered_otp != otp_store.get(mobile):
        flash("Invalid OTP. Please try again.", "danger")
        return redirect(url_for('forgot_password'))

    if new_password != confirm_password:
        flash("Passwords do not match", "danger")
        return redirect(url_for('forgot_password'))

    if len(new_password) < 6:
        flash("Password must be at least 6 characters long", "danger")
        return redirect(url_for('forgot_password'))

    user = users.find_one({"mobile_number": mobile})
    if user:
        users.update_one(
            {"_id": user["_id"]}, 
            {"$set": {"password_hash": generate_password_hash(new_password)}}
        )
        otp_store.pop(mobile, None)
        flash("Password reset successful! Please login with your new password.", "success")
    else:
        flash("User not found", "danger")
    
    return redirect(url_for('login'))

# ---------- Profile ----------
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = users.find_one({"_id": ObjectId(session['user_id'])})
    if not user:
        flash("User not found", "danger")
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Update basic info
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        mobile_number = request.form.get('mobile_number', '').strip()
        
        if not full_name:
            flash("Full name is required", "danger")
            return redirect(url_for('profile'))
        
        if not mobile_number:
            flash("Mobile number is required", "danger")
            return redirect(url_for('profile'))
        
        # Check if mobile number is already taken by another user
        existing_user = users.find_one({
            "mobile_number": mobile_number,
            "_id": {"$ne": ObjectId(session['user_id'])}
        })
        if existing_user:
            flash("Mobile number is already registered to another account", "danger")
            return redirect(url_for('profile'))
        
        update_data = {
            'full_name': full_name,
            'email': email,
            'mobile_number': mobile_number
        }

        # Handle password change
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        
        if new_password or confirm_password:
            if new_password != confirm_password:
                flash("New passwords do not match", "danger")
                return redirect(url_for('profile'))
            if len(new_password) < 6:
                flash("Password must be at least 6 characters long", "danger")
                return redirect(url_for('profile'))
            update_data['password_hash'] = generate_password_hash(new_password)

        # Handle profile photo upload
        if 'profile_photo' in request.files:
            file = request.files['profile_photo']
            if file and file.filename:
                # Validate file type
                allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
                file_extension = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
                
                if file_extension not in allowed_extensions:
                    flash("Invalid file type. Please upload PNG, JPG, JPEG, or GIF files only.", "danger")
                    return redirect(url_for('profile'))
                
                # Validate file size (5MB limit)
                file.seek(0, os.SEEK_END)
                file_size = file.tell()
                file.seek(0)
                
                if file_size > 5 * 1024 * 1024:  # 5MB
                    flash("File size too large. Please upload files smaller than 5MB.", "danger")
                    return redirect(url_for('profile'))
                
                # Save file
                filename = f"user_{session['user_id']}_{file.filename}"
                filepath = os.path.join(UPLOAD_DIR, filename)
                
                # Remove old profile photo if exists
                if user.get('profile_photo'):
                    old_path = os.path.join(UPLOAD_DIR, user['profile_photo'])
                    if os.path.exists(old_path):
                        os.remove(old_path)
                
                file.save(filepath)
                update_data['profile_photo'] = filename

        try:
            users.update_one(
                {"_id": ObjectId(session['user_id'])}, 
                {"$set": update_data}
            )
            flash("Profile updated successfully!", "success")
        except Exception as e:
            flash("An error occurred while updating your profile. Please try again.", "danger")
        
        return redirect(url_for('profile'))

    return render_template('profile.html', user=user)

# ---------- Dashboard ----------
@app.route('/dashboard')
@login_required
def dashboard():
    print(f"🔍 Dashboard accessed by user ID: {session.get('user_id')}")  # Debug
    user_batches = herb_batches.find({"user_id": session['user_id']}).sort("created_at", -1)
    user = users.find_one({"_id": ObjectId(session['user_id'])})
    print(f"🔍 Dashboard loaded for user: {user['username'] if user else 'None'}")  # Debug
    return render_template('dashboard.html', herb_batches=list(user_batches), user=user)

# ---------- Add Batch ----------
@app.route('/add_batch', methods=['POST'])
@login_required
def add_batch():
    herb_name = request.form.get('herb_name', '').strip()
    collector = request.form.get('collector_name', '').strip()
    farm_location = request.form.get('farm_location', '').strip()
    notes = request.form.get('notes', '').strip()
    latitude_str = request.form.get('latitude', '').strip()
    longitude_str = request.form.get('longitude', '').strip()

    # Validation
    if not all([herb_name, collector, farm_location]):
        flash("Herb name, collector, and farm location are required", "danger")
        return redirect(url_for('dashboard'))

    try:
        latitude = float(latitude_str) if latitude_str else 0.0
        longitude = float(longitude_str) if longitude_str else 0.0
    except ValueError:
        flash("Latitude and Longitude must be valid numbers", "danger")
        return redirect(url_for('dashboard'))

    new_batch = {
        'herb_name': herb_name,
        'collector': collector,
        'farm_location': farm_location,
        'latitude': latitude,
        'longitude': longitude,
        'notes': notes,
        'user_id': session['user_id'],
        'created_at': datetime.utcnow()
    }
    
    try:
        herb_batches.insert_one(new_batch)
        flash("New herb batch added successfully!", "success")
    except Exception as e:
        flash("An error occurred while adding the batch. Please try again.", "danger")
    
    return redirect(url_for('dashboard'))

# ---------- Edit Batch ----------
@app.route('/edit_batch/<batch_id>', methods=['GET', 'POST'])
@login_required
def edit_batch(batch_id):
    try:
        batch = herb_batches.find_one({"_id": ObjectId(batch_id)})
    except:
        flash("Invalid batch ID", "danger")
        return redirect(url_for('dashboard'))
    
    if not batch:
        flash("Batch not found", "danger")
        return redirect(url_for('dashboard'))
    
    # Ensure user can only edit their own batches
    if batch['user_id'] != session['user_id']:
        flash("You don't have permission to edit this batch", "danger")
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        herb_name = request.form.get('herb_name', '').strip()
        collector = request.form.get('collector', '').strip()
        farm_location = request.form.get('farm_location', '').strip()
        notes = request.form.get('notes', '').strip()
        latitude_str = request.form.get('latitude', '').strip()
        longitude_str = request.form.get('longitude', '').strip()
        
        if not all([herb_name, collector, farm_location]):
            flash("Herb name, collector, and farm location are required", "danger")
            return redirect(url_for('edit_batch', batch_id=batch_id))
        
        try:
            latitude = float(latitude_str) if latitude_str else 0.0
            longitude = float(longitude_str) if longitude_str else 0.0
        except ValueError:
            flash("Latitude and Longitude must be valid numbers", "danger")
            return redirect(url_for('edit_batch', batch_id=batch_id))
        
        update_data = {
            'herb_name': herb_name,
            'collector': collector,
            'farm_location': farm_location,
            'notes': notes,
            'latitude': latitude,
            'longitude': longitude
        }
        
        try:
            herb_batches.update_one(
                {"_id": ObjectId(batch_id)}, 
                {"$set": update_data}
            )
            flash("Batch updated successfully!", "success")
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash("An error occurred while updating the batch. Please try again.", "danger")
    
    return render_template('edit_batch.html', batch=batch)

# ---------- Delete Batch ----------
@app.route('/delete_batch/<batch_id>', methods=['POST'])
@login_required
def delete_batch(batch_id):
    try:
        batch = herb_batches.find_one({"_id": ObjectId(batch_id)})
    except:
        flash("Invalid batch ID", "danger")
        return redirect(url_for('dashboard'))
    
    if not batch:
        flash("Batch not found", "danger")
        return redirect(url_for('dashboard'))
    
    # Ensure user can only delete their own batches
    if batch['user_id'] != session['user_id']:
        flash("You don't have permission to delete this batch", "danger")
        return redirect(url_for('dashboard'))
    
    try:
        herb_batches.delete_one({"_id": ObjectId(batch_id)})
        flash("Batch deleted successfully!", "info")
    except Exception as e:
        flash("An error occurred while deleting the batch. Please try again.", "danger")
    
    return redirect(url_for('dashboard'))

# ---------- Provenance/Trace ----------
@app.route('/provenance/<batch_id>')
def provenance(batch_id):
    try:
        batch = herb_batches.find_one({"_id": ObjectId(batch_id)})
        if not batch:
            flash("Batch not found", "danger")
            return redirect(url_for('login'))
        return render_template('provenance.html', batch=batch)
    except:
        flash("Invalid batch ID", "danger")
        return redirect(url_for('login'))

# ---------- Generate QR ----------
@app.route('/generate_qr/<batch_id>')
@login_required
def generate_qr(batch_id):
    try:
        batch = herb_batches.find_one({"_id": ObjectId(batch_id)})
    except:
        flash("Invalid batch ID", "danger")
        return redirect(url_for('dashboard'))
    
    if not batch:
        flash("Batch not found", "danger")
        return redirect(url_for('dashboard'))
    
    # Ensure user can only generate QR for their own batches
    if batch['user_id'] != session['user_id']:
        flash("You don't have permission to generate QR code for this batch", "danger")
        return redirect(url_for('dashboard'))
    
    try:
        url = url_for('provenance', batch_id=batch_id, _external=True)
        img = qrcode.make(url)
        
        qr_filename = f'qr_{batch_id}.png'
        qr_path = os.path.join(tempfile.gettempdir(), qr_filename)
        img.save(qr_path)
        
        return send_from_directory(tempfile.gettempdir(), qr_filename)
    except Exception as e:
        flash("An error occurred while generating QR code. Please try again.", "danger")
        return redirect(url_for('dashboard'))

# ---------- Scanner ----------
@app.route('/scan')
@login_required
def scan():
    return render_template('scan.html')

# ---------- Admin Panel ----------
@app.route('/admin')
@login_required
def admin_panel():
    user = users.find_one({"_id": ObjectId(session['user_id'])})
    print(f"🔍 Admin panel access attempt by: {user['username'] if user else 'None'}")  # Debug
    
    if not user or user['username'] != 'admin':
        flash("Admin access required", "danger")
        return redirect(url_for('dashboard'))
    
    print("✅ Admin panel access granted")  # Debug
    all_users = list(users.find().sort("created_at", -1))
    all_batches = list(herb_batches.find().sort("created_at", -1))
    return render_template('admin.html', users=all_users, batches=all_batches)

# ---------- Error Handlers ----------
@app.errorhandler(404)
def not_found(error):
    flash("Page not found", "danger")
    return redirect(url_for('dashboard'))

@app.errorhandler(500)
def internal_error(error):
    flash("An internal error occurred. Please try again.", "danger")
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
