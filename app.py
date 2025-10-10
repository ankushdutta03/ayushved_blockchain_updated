from flask import Flask, render_template, send_from_directory, redirect, url_for, request, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, HerbBatch, User
import qrcode, os, random

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ayutrace.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'supersecretkey'  # Change in production

db.init_app(app)

# Create uploads directory for profile photos
os.makedirs('static/uploads', exist_ok=True)

with app.app_context():
    db.create_all()
    
    # Create admin user if it doesn't exist
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        admin_user = User(
            full_name='admin',
            username='admin',
            password_hash=generate_password_hash('Vigilant@Voices'),
            mobile_number='9999999999'
        )
        db.session.add(admin_user)
        db.session.commit()
        print("✅ Admin user created successfully!")
        print("Username: admin")
        print("Password: Vigilant@Voices")
        print("Mobile: 9999999999")

otp_store = {}  # Temporary OTP store

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

        if User.query.filter_by(username=username).first():
            flash("Username already exists", "danger")
            return redirect(url_for('signup'))

        if User.query.filter_by(mobile_number=mobile_number).first():
            flash("Mobile number already registered", "danger")
            return redirect(url_for('signup'))

        hashed_pw = generate_password_hash(password)
        new_user = User(
            full_name=full_name,
            username=username,
            password_hash=hashed_pw,
            mobile_number=mobile_number
        )
        db.session.add(new_user)
        db.session.commit()
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
        
        user = User.query.filter_by(username=username).first()
        print(f"🔍 User found in database: {user is not None}")  # Debug
        
        if user:
            print(f"🔍 User details - ID: {user.id}, Username: {user.username}")  # Debug
            password_match = check_password_hash(user.password_hash, password)
            print(f"🔍 Password match: {password_match}")  # Debug
            
            if password_match:
                # Clear any existing flash messages before login
                session.pop('_flashes', None)
                
                session['user_id'] = user.id
                session['username'] = user.username
                
                print(f"✅ Login successful! Session set - User ID: {session['user_id']}")  # Debug
                
                # Show admin welcome message for admin user
                if user.username == 'admin':
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
        
        user = User.query.filter_by(mobile_number=mobile).first()
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

    user = User.query.filter_by(mobile_number=mobile).first()
    if user:
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        otp_store.pop(mobile, None)
        flash("Password reset successful! Please login with your new password.", "success")
    else:
        flash("User not found", "danger")
    
    return redirect(url_for('login'))

# ---------- Profile ----------
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = User.query.get(session['user_id'])
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
        existing_user = User.query.filter(
            User.mobile_number == mobile_number,
            User.id != user.id
        ).first()
        if existing_user:
            flash("Mobile number is already registered to another account", "danger")
            return redirect(url_for('profile'))
        
        user.full_name = full_name
        user.email = email
        user.mobile_number = mobile_number

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
            user.password_hash = generate_password_hash(new_password)

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
                filename = f"user_{user.id}_{file.filename}"
                filepath = os.path.join('static/uploads', filename)
                
                # Remove old profile photo if exists
                if user.profile_photo:
                    old_path = os.path.join('static/uploads', user.profile_photo)
                    if os.path.exists(old_path):
                        os.remove(old_path)
                
                file.save(filepath)
                user.profile_photo = filename

        try:
            db.session.commit()
            flash("Profile updated successfully!", "success")
        except Exception as e:
            db.session.rollback()
            flash("An error occurred while updating your profile. Please try again.", "danger")
        
        return redirect(url_for('profile'))

    return render_template('profile.html', user=user)

# ---------- Dashboard ----------
@app.route('/dashboard')
@login_required
def dashboard():
    print(f"🔍 Dashboard accessed by user ID: {session.get('user_id')}")  # Debug
    batches = HerbBatch.query.filter_by(user_id=session['user_id']).order_by(HerbBatch.id.desc()).all()
    user = User.query.get(session['user_id'])
    print(f"🔍 Dashboard loaded for user: {user.username if user else 'None'}")  # Debug
    return render_template('dashboard.html', herb_batches=batches, user=user)

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

    new_batch = HerbBatch(
        herb_name=herb_name,
        collector=collector,
        farm_location=farm_location,
        latitude=latitude,
        longitude=longitude,
        notes=notes,
        user_id=session['user_id']
    )
    
    try:
        db.session.add(new_batch)
        db.session.commit()
        flash("New herb batch added successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash("An error occurred while adding the batch. Please try again.", "danger")
    
    return redirect(url_for('dashboard'))

# ---------- Edit Batch ----------
@app.route('/edit_batch/<int:batch_id>', methods=['GET', 'POST'])
@login_required
def edit_batch(batch_id):
    batch = HerbBatch.query.get_or_404(batch_id)
    
    # Ensure user can only edit their own batches
    if batch.user_id != session['user_id']:
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
        
        batch.herb_name = herb_name
        batch.collector = collector
        batch.farm_location = farm_location
        batch.notes = notes
        batch.latitude = latitude
        batch.longitude = longitude
        
        try:
            db.session.commit()
            flash("Batch updated successfully!", "success")
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash("An error occurred while updating the batch. Please try again.", "danger")
    
    return render_template('edit_batch.html', batch=batch)

# ---------- Delete Batch ----------
@app.route('/delete_batch/<int:batch_id>', methods=['POST'])
@login_required
def delete_batch(batch_id):
    batch = HerbBatch.query.get_or_404(batch_id)
    
    # Ensure user can only delete their own batches
    if batch.user_id != session['user_id']:
        flash("You don't have permission to delete this batch", "danger")
        return redirect(url_for('dashboard'))
    
    try:
        db.session.delete(batch)
        db.session.commit()
        flash("Batch deleted successfully!", "info")
    except Exception as e:
        db.session.rollback()
        flash("An error occurred while deleting the batch. Please try again.", "danger")
    
    return redirect(url_for('dashboard'))

# ---------- Provenance/Trace ----------
@app.route('/provenance/<int:batch_id>')
def provenance(batch_id):
    batch = HerbBatch.query.get_or_404(batch_id)
    return render_template('provenance.html', batch=batch)

# ---------- Generate QR ----------
@app.route('/generate_qr/<int:batch_id>')
@login_required
def generate_qr(batch_id):
    batch = HerbBatch.query.get_or_404(batch_id)
    
    # Ensure user can only generate QR for their own batches
    if batch.user_id != session['user_id']:
        flash("You don't have permission to generate QR code for this batch", "danger")
        return redirect(url_for('dashboard'))
    
    try:
        url = url_for('provenance', batch_id=batch_id, _external=True)
        img = qrcode.make(url)
        os.makedirs('static', exist_ok=True)
        out_path = os.path.join('static', f'qr_{batch_id}.png')
        img.save(out_path)
        return send_from_directory('static', f'qr_{batch_id}.png')
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
    user = User.query.get(session['user_id'])
    print(f"🔍 Admin panel access attempt by: {user.username if user else 'None'}")  # Debug
    
    if not user or user.username != 'admin':
        flash("Admin access required", "danger")
        return redirect(url_for('dashboard'))
    
    print("✅ Admin panel access granted")  # Debug
    users = User.query.order_by(User.id.desc()).all()
    batches = HerbBatch.query.order_by(HerbBatch.id.desc()).all()
    return render_template('admin.html', users=users, batches=batches)

# ---------- Error Handlers ----------
@app.errorhandler(404)
def not_found(error):
    flash("Page not found", "danger")
    return redirect(url_for('dashboard'))

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    flash("An internal error occurred. Please try again.", "danger")
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
