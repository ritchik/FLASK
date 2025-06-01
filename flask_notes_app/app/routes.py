from flask import Blueprint, render_template, request, redirect, url_for, flash, session, send_file
from app.models import Note, User, SharedNote,LoginHistory
from flask_mail import Message,Mail
from flask import current_app
from app import mail,csrf, limiter
from app.forms import ForgotPasswordForm, ResetPasswordForm, LoginForm,Verify2FAForm,AddNoteForm
#from . import app
#from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from app import db
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
import hashlib 
import pyotp
import geoip2.database
from flask import jsonify
from flask_wtf.csrf import CSRFProtect, generate_csrf
import io
from flask import render_template, request, flash, redirect, url_for, session
from flask_login import login_user, logout_user, login_required, current_user
import time
from flask import abort 
from flask import current_app as app 
 
import uuid
import geoip2.database
from app.email import send_email 
import markdown
import pyqrcode
from io import BytesIO
import base64
import re
import os
from werkzeug.utils import secure_filename  
from app.PasswordManager import LoginAttemptTracker, PasswordManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

main = Blueprint('main', __name__)



def get_location_from_ip(ip_address):
    if ip_address.startswith(('10.', '172.', '192.168.')):
        return "Local Network"
    
    try:
        with geoip2.database.Reader('GeoLite2-City.mmdb') as reader:
            response = reader.city(ip_address)
            return f"{response.city.name}, {response.country.name}"
    except Exception:
        return "Unknown"

def generate_session_id():
    """Generate unique session identifier"""
    return str(uuid.uuid4())

def get_location(ip_address):
    """Get approximate location from IP address"""
    try:
        with geoip2.database.Reader('GeoLite2-City.mmdb') as reader:
            response = reader.city(ip_address)
            return f"{response.city.name}, {response.country.name}"
    except:
        return "Unknown"

def detect_suspicious_login(user_id, request):
    """Check for unusual login patterns"""
    from app.models import LoginHistory  # Avoid circular imports
    
    # Get last 5 logins
    last_logins = LoginHistory.query.filter_by(user_id=user_id)\
                      .order_by(LoginHistory.login_time.desc())\
                      .limit(5)\
                      .all()
    
    if not last_logins:
        return False
    
    current_ip = request.remote_addr
    current_agent = request.headers.get('User-Agent')
    
    # Check if IP or device changed
    for login in last_logins:
        if login.ip_address != current_ip or login.user_agent != current_agent:
            return True
    
    return False

def send_security_alert(user):
    """Send email notification about suspicious login"""
    subject = "Security Alert: New Login Detected"
    template = "email/security_alert.html"
    send_email(user.email, subject, template, user=user)




def check_honeypot(request):
    """Check honeypot field in form submissions"""
    if request.method == "POST":
        honeypot = request.form.get("honeypot")
        if honeypot and honeypot.strip():
            current_app.logger.warning(
                f"Honeypot triggered - Bot detected from {request.remote_addr} | "
                f"User-Agent: {request.headers.get('User-Agent')} | "
                f"Attempted username: {request.form.get('username', '')}"
            )
            abort(403, description="Invalid form submission")




@main.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf())

def generate_signature(user_id, content):
    data = f"{user_id}:{content}"
    return hashlib.sha256(data.encode()).hexdigest()
 
def verify_signature(note):
    expected_signature = generate_signature(note.user_id, note.content_md)
    return expected_signature == note.signature

def check_honeypot(request):
    """Check honeypot field in form submissions"""
    if request.method == "POST":
        honeypot = request.form.get("honeypot")
        if honeypot and honeypot.strip() != "":
            app.logger.warning(f"Bot detected via honeypot from {request.remote_addr}")
            abort(403)


def test_honeypot_protection(self):
    # Test valid submission
    response = self.client.post('/login', data={
        'username': 'testuser',
        'password': 'testpass',
        'honeypot': '',  # Empty honeypot
        'csrf_token': generate_csrf()
    })
    self.assertNotEqual(response.status_code, 403)
    
    # Test bot submission
    response = self.client.post('/login', data={
        'username': 'botuser',
        'password': 'botpass',
        'honeypot': 'filled',  # Honeypot filled
        'csrf_token': generate_csrf()
    })
    self.assertEqual(response.status_code, 403)            

@main.route("/") 
def index():
    return redirect(url_for('main.login'))

 

@main.route("/login", methods=['GET', 'POST'])
@limiter.limit("15 per minute", key_func=lambda: f"login_global_{request.remote_addr}")  # Global IP-based limit
@limiter.limit("5 per minute", key_func=lambda: f"login_user_{session.get('_id', 'anon')}")  # Per-session limit
def login():
    check_honeypot(request)
    
    if current_user.is_authenticated:
        return redirect(url_for('main.profile'))
    
    form = LoginForm()
    
    # Initialize security tracking
    if 'failed_attempts' not in session:
        session['failed_attempts'] = 0
        session['_id'] = str(uuid.uuid4())  # Unique session identifier
        session['first_failed_time'] = None
        session['lockout_phase'] = 0  # Track which phase of lockout we're in
    
    # Progressive lockout system (5 fails → 30s, next 5 → 40s, next 5 → 50s, next 5+ → 60s)
    lockout_durations = [30, 40, 50, 60]  # Increasing lockout durations
    current_phase = min(session.get('lockout_phase', 0), len(lockout_durations) - 1)
    current_lockout = lockout_durations[current_phase] if session['failed_attempts'] >= 5 else 0
    
    # Check if in lockout period
    if current_lockout > 0:
        elapsed = time.time() - session.get('lock_time', 0)
        remaining = max(0, current_lockout - elapsed)
        if remaining > 0:
            flash(f'Too many failed attempts. Please try again in {int(remaining)} seconds', 'danger')
            return render_template('login.html', 
                                form=form,
                                is_locked=True,
                                remaining_time=int(remaining))
        else:
            # Lockout period expired - reset attempts but keep phase
            session['failed_attempts'] = 0

    # Add progressive delay for failed attempts (1s per failed attempt, max 5s)
    if session['failed_attempts'] > 0:
        delay = min(session['failed_attempts'], 5)
        time.sleep(delay)

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user:
            if PasswordManager.verify_password(user.password_hash, form.password.data):
                # Successful login - reset all security counters
                session.pop('failed_attempts', None)
                session.pop('lock_time', None)
                session.pop('lockout_phase', None)
                login_user(user)
                
                # Log login history
                try:
                    login_history = LoginHistory(
                        user_id=user.id,
                        ip_address=request.remote_addr,
                        user_agent=request.headers.get('User-Agent'),
                        location=get_location(request.remote_addr)
                    )
                    db.session.add(login_history)
                    db.session.commit()
                    
                    if detect_suspicious_login(user.id, request):
                        send_security_alert(user)
                        flash('Security alert: Unusual login detected', 'warning')
                
                except Exception as e:
                    current_app.logger.error(f"Login history error: {str(e)}")
                
                flash('Login successful!', 'success')
                return redirect(url_for('main.profile'))
            else:
                # Failed attempt
                session['failed_attempts'] = session.get('failed_attempts', 0) + 1
                if session['failed_attempts'] == 1:
                    session['first_failed_time'] = time.time()
                
                # Check if we've reached a multiple of 5 failed attempts
                if session['failed_attempts'] % 5 == 0:
                    session['lockout_phase'] = min(
                        session.get('lockout_phase', 0) + 1,
                        len(lockout_durations) - 1
                    )
                    session['lock_time'] = time.time()
                    current_lockout = lockout_durations[session['lockout_phase']]
                    flash(f'Account temporarily locked for {current_lockout} seconds', 'danger')
                
                flash('Invalid credentials', 'danger')
        else:
            # Unknown username
            session['failed_attempts'] = session.get('failed_attempts', 0) + 1
            flash('Invalid credentials', 'danger')

    return render_template('login.html', 
                         form=form, 
                         is_locked=False,
                         remaining_time=0)
@main.route('/profile')
@login_required
def profile():
   # check_honeypot(request)

    if not current_user.is_2fa_verified:
        return redirect(url_for('main.verify_2fa'))
    
    # Get private notes (user's own notes that aren't public)
    private_notes = Note.query.filter_by(
        user_id=current_user.id,
        is_public=False
    ).all()
    
    # Get public notes (user's own public notes)
    public_notes = Note.query.filter_by(
        user_id=current_user.id,
        is_public=True
    ).all()
    
    # Get shared notes (notes shared specifically with the user)
    shared_notes = Note.query.join(SharedNote).filter(
        SharedNote.user_id == current_user.id
    ).all()
    
    # Get all public notes from other users
    other_public_notes = Note.query.filter(
        Note.is_public == True,
        Note.user_id != current_user.id
    ).all()
    
    
    other_users = User.query.filter(User.id != current_user.id).all()


    return render_template(
        'profile.html',
        user=current_user,
        private_notes=private_notes,
        public_notes=public_notes,
        shared_notes=shared_notes,
        other_public_notes=other_public_notes,
        other_users=other_users
    )

 
@main.route('/logout')
@login_required
def logout():
   
    

    # Reset 2FA verification status and logout user
    current_user.is_2fa_verified = False  # Reset 2FA verification on logout
    db.session.commit()

    # Debugging: Check session data before logout
    print("Before logout:", session)
    print("Before logout:", current_user.is_authenticated)

    logout_user()  # Logs out the user
    session.clear()  # Ensure session is completely cleared

    # Debugging: Check session data after logout
    print("After logout:", session)
    print("After logout:", current_user.is_authenticated)  # Should be False

    flash("You have been logged out.", "info")
    return redirect(url_for('main.login'))

 
# @main.route("/")   
@main.route("/notes")
@login_required
def list_notes():

   
    notes = Note.query.filter_by(user_id=current_user.id).all()
    for note in notes:
        if note.content_md:
            note.content_html = markdown.markdown(note.content_md)
        else:
            note.content_html = ""
        note.signature_valid = note.verify_signature(current_user)  # Check if signature is valid
    return render_template("notes.html", notes=notes)


 
@main.route('/note/<int:note_id>', methods=['GET', 'POST'])
@login_required
def view_note(note_id):

     
   

    note = Note.query.get_or_404(note_id)

    # Check if the user has access to the note
    if not note.is_accessible_by(current_user):
        flash("Nie masz dostępu do tej notatki!", "danger")
        return redirect(url_for("main.list_notes"))

    # Decrypt note if it's encrypted
    if note.encrypted:
        if request.method == "POST":
            password = request.form["password"]
            decrypted_content = note.decrypt_content(password)

            if decrypted_content:
                content_html = markdown.markdown(decrypted_content)
                note.signature_valid = note.verify_signature(current_user)  # Verify signature after decryption
                return render_template("note.html", note=note, content=content_html)
            else:
                flash("Błędne hasło.", "danger")

        return render_template("note.html", note=note)

    note.content_html = markdown.markdown(note.content_md)
    note.signature_valid = note.verify_signature(current_user)  # Verify signature
    return render_template("note.html", note=note, content=note.content_html)


     
 
@main.route("/sign_note/<int:note_id>", methods=["POST"])
@login_required
def sign_note_route(note_id):

 

    note = Note.query.get_or_404(note_id)

    # Check if the note belongs to the current user
    if note.user_id != current_user.id:
        flash("Nie masz uprawnień do podpisania tej notatki.", "danger")
        return redirect(url_for("main.list_notes"))

    try:
        # Sign the note
        note.sign_note(current_user)
        db.session.commit()
        flash("Notatka została podpisana.", "success")
    except ValueError:
        flash("Brak klucza prywatnego. Możesz wygenerować go w swoim profilu.", "danger")

    return redirect(url_for("main.view_note", note_id=note.id))

 

@main.route("/delete/<int:note_id>", methods=["POST"])
@login_required
def delete_note(note_id):

  

    note = Note.query.get_or_404(note_id)
    if note.user_id != current_user.id:
        flash('You do not have permission to delete this note.')
        return redirect(url_for('main.list_notes'))
    db.session.delete(note)
    db.session.commit()
    return redirect(url_for("main.list_notes"))



@main.route('/register', methods=['GET', 'POST'])
def register():
    check_honeypot(request)

     

    if request.method == 'POST':

        
        print(f"CSRF token in form: {request.form.get('csrf_token')}")

        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form.get('email', '')

        # Walidacja danych wejściowych
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
            flash('Nieprawidłowa nazwa użytkownika', 'error')
            return redirect(url_for('main.register'))

        # Weryfikacja siły hasła
        password_strength = PasswordManager.validate_password_strength(
            password, username, email
        )

        if not password_strength['is_strong']:
            # Szczegółowe wskazówki dotyczące słabości hasła
            weakness_messages = {
                'min_length': 'Hasło musi mieć min. 12 znaków',
                'has_uppercase': 'Wymagana wielka litera',
                'has_lowercase': 'Wymagana mała litera',
                'has_digit': 'Wymagana cyfra',
                'has_special_char': 'Wymagany znak specjalny'
            }
            
            weakness_hints = [
                msg for check, msg in weakness_messages.items() 
                if not password_strength['additional_checks'][check]
            ]

            flash(f"Słabe hasło. {' '.join(weakness_hints)}", 'warning')
            return redirect(url_for('main.register'))

        # Weryfikacja zgodności haseł
        if password != confirm_password:
            flash('Hasła nie są identyczne', 'error')
            return redirect(url_for('main.register'))

        # Sprawdzenie unikalności użytkownika
        if User.query.filter_by(username=username).first():
            flash('Użytkownik już istnieje', 'error')
            return redirect(url_for('main.register'))

        # Opcjonalna weryfikacja unikalności emaila
        if email and User.query.filter_by(email=email).first():
            flash('Email jest już używany', 'error')
            return redirect(url_for('main.register'))

        # Generowanie soli i hashowanie hasła
        password_hash = PasswordManager.hash_password(password)

        # Generowanie TOTP dla 2FA
        totp_secret = pyotp.random_base32()

        # Tworzenie użytkownika
        user = User(
            username=username,
            email=email,
            password_hash=password_hash,
            totp_secret=totp_secret
        )

         # Generowanie kluczy RSA podczas rejestracji
        user.generate_keys()

        try:
            db.session.add(user)
            print('after adding')
            print(f'url: {db.engine.url}')
            db.session.commit()
            print('after commit')
            flash('Rejestracja zakończona sukcesem', 'success')
            return redirect(url_for('main.login'))
        except Exception as e:
            db.session.rollback()
            flash('Wystąpił błąd podczas rejestracji', 'error')
            return redirect(url_for('main.register'))

    return render_template('register.html')

  
  
@main.route("/add", methods=["GET", "POST"])
@login_required
def add_note():

 
    if request.method == "POST":
        try:
            

            # Get data directly from request.form (no Flask-WTF form)
            title = request.form.get("title")
            content = request.form.get("content_md")
            is_public = request.form.get("is_public") == "true"  # Checkbox handling
            password = request.form.get("password")

            new_note = Note(
                title=title,
                content_md=content,
                user_id=current_user.id,
                is_public=is_public
            )

            if password:
                new_note.encrypt_content(password)

            db.session.add(new_note)
            
            if not current_user.private_key:
                current_user.generate_keys()
                db.session.commit()
                flash('Wygenerowano nowe klucze bezpieczeństwa.', 'info')
            
            new_note.sign_note(current_user)
            db.session.commit()
            
            flash('Notatka dodana i podpisana pomyślnie!', 'success')
            return redirect(url_for('main.profile'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Błąd podczas dodawania notatki: {str(e)}', 'danger')

    return render_template("add_note.html")  # No form object passed


 

@main.route('/regenerate_keys', methods=['POST'])
@login_required
def regenerate_keys():
    
 

    try:
        current_user.generate_keys()
        db.session.commit()
        flash('Klucze bezpieczeństwa zostały zregenerowane pomyślnie', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Błąd podczas regeneracji kluczy: {str(e)}', 'danger')
    
    return redirect(url_for('main.profile'))


@main.route('/verify_2fa', methods=['GET', 'POST'])
@login_required  # Ensure only logged-in users can access
def verify_2fa():
    form = Verify2FAForm()  # Use the new form


    if request.method == 'POST':
        otp = request.form.get('otp')
        if not otp:
            flash("Please enter the OTP code.", "error")
            return redirect(url_for('main.verify_2fa'))
        if form.validate_on_submit():
           otp = form.otp.data

        totp = pyotp.TOTP(current_user.totp_secret)
        
        if totp.verify(otp):
            current_user.is_2fa_verified = True
            db.session.commit()
            
            return redirect(url_for('main.profile'))
        else:
            flash("Invalid OTP code. Please try again.", "error")
    
    # Display QR code for 2FA setup
    totp = pyotp.TOTP(current_user.totp_secret)
    provisioning_uri = totp.provisioning_uri(
        name=current_user.username,
        issuer_name="SecureNotes"
    )

    # Generate QR code
    qr = pyqrcode.create(provisioning_uri)
    buffer = BytesIO()
    qr.png(buffer, scale=6)
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
            
    return render_template('verify_2fa.html',
                           form=form, 
                         qr_code=qr_code_base64, 
                         secret=current_user.totp_secret)


 

def save_image(image):
    image_filename = secure_filename(image.filename)
    image_path = os.path.join('static/images', image_filename)
    image.save(image_path)
    return image_path



@main.route("/addimage", methods=["GET", "POST"])
@login_required
def add_image():
 
    if request.method == "POST":
        title = request.form["title"]
        content_md = request.form["content_md"]
        password = request.form.get('password')  # Pobierz hasło, jeśli podane
        
        # Optionally handle image upload here, e.g., save to a static folder
        image_file = request.files.get("image")
        if image_file:
            # Save the image and add the URL to the markdown content
            image_path = save_image(image_file)  # Implement save_image function to save and return path
            content_md += f"\n![Image]({image_path})"  # Add the image URL to the markdown content

        # Tworzenie podpisu
        signature = generate_signature(current_user.id, content_md)

        new_note = Note(
            title=title, 
            content_md=content_md, 
            user_id=current_user.id,
            signature=signature  # Przechowywanie podpisu w bazie
        )

        if password:
            new_note.encrypt_content(password)  # Szyfrowanie notatki, jeśli podano hasło
        
        db.session.add(new_note)
        db.session.commit()
        
        flash('Note added successfully!', 'success')
        return redirect(url_for('main.list_notes'))  # Lub inna strona

    return render_template("add_note.html")

 
 
@main.route('/toggle_visibility/<int:note_id>', methods=['POST'])
@login_required
def toggle_visibility(note_id):
     
    note = Note.query.get_or_404(note_id)
    
    if note.user_id != current_user.id:
        flash('You do not have permission to modify this note.', 'danger')
        return redirect(url_for('main.profile'))
    
    note.is_public = not note.is_public
    db.session.commit()
    
    status = "public" if note.is_public else "private"
    flash(f'Note visibility changed to {status}', 'success')
    return redirect(url_for('main.profile'))



@main.route('/share/<int:note_id>', methods=['POST'])
@login_required
def share_note(note_id):
     
    note = Note.query.get_or_404(note_id)

    if note.user_id != current_user.id:
        flash("You can only share your own notes.", "danger")
        return redirect(url_for('main.list_notes'))

    username = request.form.get("username")
    user = User.query.filter_by(username=username).first()

    if not user:
        flash("User not found!", "danger")
        return redirect(url_for('main.list_notes'))

    existing_share = SharedNote.query.filter_by(note_id=note.id, user_id=user.id).first()
    if existing_share:
        flash("Note already shared with this user.", "info")
    else:
        shared_note = SharedNote(note_id=note.id, user_id=user.id)
        db.session.add(shared_note)
        db.session.commit()
        flash("Note shared successfully!", "success")

    return redirect(url_for('main.list_notes'))


@main.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()  # Create a form class
    
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        
        if user:
            serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
            token = serializer.dumps({'user_id': user.id}, salt='password-reset')
            
            reset_url = url_for('main.reset_password', token=token, _external=True)
            
            # Send email
            msg = Message('Password Reset Request',
                         sender='noreply@yourdomain.com',
                         recipients=[email])
            msg.body = f'Click to reset your password: {reset_url}'
            mail.send(msg)
            
            flash('Password reset link sent to your email.', 'info')
            return redirect(url_for('main.login'))
        
        flash('No account found with that email.', 'danger')
    
    return render_template('forgot_password.html', form=form)

@main.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        data = serializer.loads(token, salt='password-reset', max_age=3600)
        user = User.query.get(data['user_id'])
        
        if not user:
            flash('Invalid user', 'danger')
            return redirect(url_for('main.login'))

        form = ResetPasswordForm()
        
        if form.validate_on_submit():
            password = form.password.data
            confirm_password = form.confirm_password.data
            
            # Verify passwords match
            if password != confirm_password:
                flash('Hasła nie są identyczne', 'error')
                return render_template('reset_password.html', form=form, token=token)
            
            # Verify password strength (same as registration)
            password_strength = PasswordManager.validate_password_strength(
                password, user.username, user.email
            )
            
            if not password_strength['is_strong']:
                # Detailed password weakness messages
                weakness_messages = {
                    'min_length': 'Hasło musi mieć min. 12 znaków',
                    'has_uppercase': 'Wymagana wielka litera',
                    'has_lowercase': 'Wymagana mała litera',
                    'has_digit': 'Wymagana cyfra',
                    'has_special_char': 'Wymagany znak specjalny'
                }
                
                weakness_hints = [
                    msg for check, msg in weakness_messages.items() 
                    if not password_strength['additional_checks'][check]
                ]

                flash(f"Słabe hasło. {' '.join(weakness_hints)}", 'warning')
                return render_template('reset_password.html', form=form, token=token)
            
            # Hash and save the password
            hashed_password = PasswordManager.hash_password(password)
            user.password_hash = hashed_password
            db.session.commit()
            
            flash('Password updated successfully! Please login with your new password.', 'success')
            return redirect(url_for('main.login'))
            
    except (BadSignature, SignatureExpired) as e:
        flash('Invalid or expired token', 'danger')
        return redirect(url_for('main.login'))
    
    return render_template('reset_password.html', form=form, token=token)


@main.route('/get-csrf-token', methods=['GET'])
def get_csrf_token():
    return jsonify({'csrf_token': generate_csrf()})



@main.route('/profile/login_history')
@login_required
def login_history():
    history = LoginHistory.query.filter_by(user_id=current_user.id).order_by(LoginHistory.login_time.desc()).all()
    return render_template('login_history.html', history=history)


@main.route("/note/<int:note_id>/download-signature")
@login_required
def download_signature(note_id):
    note = Note.query.get_or_404(note_id)
    
    # Sprawdzenie czy użytkownik ma dostęp do notatki
    if not note.is_accessible_by(current_user):
        abort(403)

    signature_data = f"--- PODPIS NOTATKI ---\nAutor: {note.author.username}\nID Notatki: {note.id}\nPodpis (base64):\n{note.signature}"
    return send_file(
        io.BytesIO(signature_data.encode("utf-8")),
        mimetype="text/plain",
        as_attachment=True,
        download_name=f"signature_note_{note.id}.txt"
    )

@main.route("/user/<int:user_id>/download-public-key")
@login_required
def download_public_key(user_id):
    user = User.query.get_or_404(user_id)

    # Możesz ograniczyć, żeby tylko autor mógł pobrać swój klucz, albo każdy mógł widzieć
    if user != current_user and not any(note.author_id == user.id for note in current_user.notes):
        abort(403)

    if not user.public_key:
        return "Użytkownik nie ma jeszcze klucza publicznego", 404

    return send_file(
        io.BytesIO(user.public_key.encode("utf-8")),
        mimetype="text/plain",
        as_attachment=True,
        download_name=f"{user.username}_public_key.pem"
    )

@main.route('/health')
def health_check():
    return jsonify({"status": "healthy"}), 200