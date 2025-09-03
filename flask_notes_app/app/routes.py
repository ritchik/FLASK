import base64
import hashlib
import os
import re
import time
import uuid
from io import BytesIO

import markdown
import pyotp
import pyqrcode
import requests
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
 
from flask import current_app as app

from flask import (
    Blueprint, 
    render_template, 
    request, 
    redirect, 
    url_for, 
    flash, 
    session, 
    current_app,
    abort,
    jsonify
)
from flask_login import login_user, logout_user, login_required, current_user
 
from flask_wtf.csrf import generate_csrf
from app import db, mail, csrf, limiter
from app.models import Note, User, SharedNote, LoginHistory
from app.forms import (
    PasswordResetRequestForm,   
    PasswordResetForm,          
    LoginForm, 
    Verify2FAForm,
    RegistrationForm,          
    PasswordManager            
)
from app.email import send_email
 
 
 
main = Blueprint('main', __name__)



 

def get_location_from_ip(ip_address):
    if ip_address.startswith(('10.', '172.', '192.168.', '127.')):
        return "Local Network"
    
    try:
         
        response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                return f"{data['city']}, {data['country']}"
    except Exception:
        pass
    
    return "Unknown"

 
 

 

def detect_suspicious_login(user_id, request):
    """Check for unusual login patterns"""
    from app.models import LoginHistory   
    
     
    last_logins = LoginHistory.query.filter_by(user_id=user_id)\
                      .order_by(LoginHistory.login_time.desc())\
                      .limit(5)\
                      .all()
    
    if not last_logins:
        return False
    
    current_ip = request.remote_addr
    current_agent = request.headers.get('User-Agent')
    
     
    for login in last_logins:
        if login.ip_address != current_ip or login.user_agent != current_agent:
            return True
    
    return False

 
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

 


          

@main.route("/") 
def index():
    return redirect(url_for('main.login'))

 

 

@main.route("/login", methods=['GET', 'POST'])
@limiter.limit("15 per minute", key_func=lambda: f"login_global_{request.remote_addr}")   
@limiter.limit("5 per minute", key_func=lambda: f"login_user_{session.get('_id', 'anon')}")   
def login():
    check_honeypot(request)
    
    if current_user.is_authenticated:
        return redirect(url_for('main.profile'))
    
    form = LoginForm()
    
    # inicjalizacja sesji
    if 'failed_attempts' not in session:
        session['failed_attempts'] = 0
        session['_id'] = str(uuid.uuid4())
        session['first_failed_time'] = None
        session['lockout_phase'] = 0
        session['lock_time'] = None

    lockout_durations = [30, 40, 50, 60]  # w sekundach
    
    # funkcja sprawdzająca blokadę
    def check_lockout():
        if session.get('lock_time') is None:
            return False, None

        current_phase = min(session.get('lockout_phase', 0), len(lockout_durations) - 1)
        lockout_duration = lockout_durations[current_phase]

        elapsed = time.time() - session['lock_time']
        remaining = max(0, lockout_duration - elapsed)

        if remaining > 0:
            lock_end_timestamp = time.time() + remaining
            return True, int(lock_end_timestamp)
        else:
            session['lock_time'] = None
            session['failed_attempts'] = 0
            return False, None

    # sprawdzenie czy konto jest zablokowane
    is_locked, lock_end_timestamp = check_lockout()

    if is_locked:
        flash(f'Too many failed attempts. Please try again in {int(lock_end_timestamp - time.time())} seconds', 'danger')
        return render_template('login.html',
                               form=form,
                               is_locked=True,
                               lock_end_timestamp=lock_end_timestamp)

    # wprowadzenie opóźnienia dla kilku nieudanych prób
    if session.get('failed_attempts', 0) > 0:
        delay = min(session['failed_attempts'], 5)
        time.sleep(delay)

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and PasswordManager.verify_password(user.password_hash, form.password.data):
            # resetowanie danych sesji po poprawnym logowaniu
            session.pop('failed_attempts', None)
            session.pop('lock_time', None)
            session.pop('lockout_phase', None)
            session.pop('first_failed_time', None)
            login_user(user)

            try:
                login_history = LoginHistory(
                    user_id=user.id,
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent'),
                    location=get_location_from_ip(request.remote_addr)
                )
                db.session.add(login_history)
                db.session.commit()
                
                if detect_suspicious_login(user.id, request):
                    flash('Security alert: Unusual login detected', 'warning')
            except Exception as e:
                current_app.logger.error(f"Login history error: {str(e)}")

            flash('Login successful!', 'success')
            return redirect(url_for('main.profile'))

        else:
            # nieudane logowanie
            session['failed_attempts'] = session.get('failed_attempts', 0) + 1

            if session['failed_attempts'] == 1:
                session['first_failed_time'] = time.time()

            # blokada po 5 nieudanych próbach
            if session['failed_attempts'] % 5 == 0:
                session['lockout_phase'] = min(
                    session.get('lockout_phase', 0) + 1,
                    len(lockout_durations) - 1
                )
                session['lock_time'] = time.time()
                current_phase = session['lockout_phase'] - 1
                lockout_duration = lockout_durations[current_phase]

                 
                return render_template('login.html',
                                       form=form,
                                       is_locked=True,
                                       lock_end_timestamp=int(time.time() + lockout_duration))
            else:
                remaining_until_lockout = 5 - (session['failed_attempts'] % 5)
                flash(f'Invalid credentials. {remaining_until_lockout} attempts remaining before lockout.', 'danger')

    return render_template('login.html',
                           form=form,
                           is_locked=False,
                           lock_end_timestamp=None)



@main.route('/profile')
@login_required
def profile():
    if not current_user.is_2fa_verified:
        return redirect(url_for('main.verify_2fa'))
    
     
    private_notes = Note.query.filter_by(
        user_id=current_user.id,
        is_public=False
    ).all()
    
   
    public_notes = Note.query.filter_by(
        user_id=current_user.id,
        is_public=True
    ).all()
    
     
    shared_notes = Note.query.join(SharedNote).filter(
        SharedNote.user_id == current_user.id
    ).all()
    
    
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
   
    

     
    current_user.is_2fa_verified = False   
    db.session.commit()

     
     
    logout_user()  
    session.clear()   

     
     
    flash("You have been logged out.", "info")
    return redirect(url_for('main.login'))

 
  
 


 
@main.route('/note/<int:note_id>', methods=['GET', 'POST'])
@login_required
def view_note(note_id):

     
   

    note = Note.query.get_or_404(note_id)

     
    if not note.is_accessible_by(current_user):
        flash("Nie masz dostępu do tej notatki!", "danger")
        return redirect(url_for("main.profile"))

     
    if note.encrypted:
        if request.method == "POST":
            password = request.form["password"]
            decrypted_content = note.decrypt_content(password)

            if decrypted_content:
                content_html = markdown.markdown(decrypted_content)
                note.signature_valid = note.verify_signature(note.author)   
                return render_template("note.html", note=note, content=content_html)
            else:
                flash("Błędne hasło.", "danger")

        return render_template("note.html", note=note)

    note.content_html = markdown.markdown(note.content_md)
    note.signature_valid = note.verify_signature(note.author)   
    return render_template("note.html", note=note, content=note.content_html)


     
 
@main.route("/sign_note/<int:note_id>", methods=["POST"])
@login_required
def sign_note_route(note_id):

 

    note = Note.query.get_or_404(note_id)

     
    if note.user_id != current_user.id:
        flash("Nie masz uprawnień do podpisania tej notatki.", "danger")
        return redirect(url_for("main.profile"))

    try:
         
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
        return redirect(url_for('main.profile'))
    db.session.delete(note)
    db.session.commit()
    return redirect(url_for("main.profile"))



@main.route('/register', methods=['GET', 'POST'])
def register():
    check_honeypot(request)
    form = RegistrationForm()
    
    if form.validate_on_submit():  # Cała walidacja w formie!
        user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=PasswordManager.hash_password(form.password.data),
            totp_secret=pyotp.random_base32()
        )
        user.generate_keys()

        try:
            db.session.add(user)
            db.session.commit()
            flash('Registration successful!', 'success')
            return redirect(url_for('main.login'))
        except Exception as e:
            db.session.rollback()
            flash('Registration error', 'error')

    return render_template('register.html', form=form)

  
  
  
@main.route("/add", methods=["GET", "POST"])
@login_required
def add_note():
    if request.method == "POST":
        try:
            title = request.form.get("title")
            content = request.form.get("content_md")
            is_public = request.form.get("is_public") == "true"
            password = request.form.get("password")

            new_note = Note(
                title=title,
                content_md=content,   
                user_id=current_user.id,
                is_public=is_public
            )

             
            if not current_user.private_key:
                current_user.generate_keys()
                db.session.flush()   
                flash('Wygenerowano nowe klucze bezpieczeństwa.', 'info')
            
            new_note.sign_note(current_user)
            
            if password:
                new_note.encrypt_content(password)
            
            db.session.add(new_note)
            db.session.commit()   
            
            flash('Notatka dodana i podpisana pomyslnie!', 'success')
            return redirect(url_for('main.profile'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Błąd podczas dodawania notatki: {str(e)}', 'danger')

    return render_template("add_note.html")


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
@login_required   
def verify_2fa():
    form = Verify2FAForm()   


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
    
     
    totp = pyotp.TOTP(current_user.totp_secret)
    provisioning_uri = totp.provisioning_uri(
        name=current_user.username,
        issuer_name="SecureNotes"
    )

     
    qr = pyqrcode.create(provisioning_uri)
    buffer = BytesIO()
    qr.png(buffer, scale=6)
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
            
    return render_template('verify_2fa.html',
                           form=form, 
                           qr_code=qr_code_base64, 
                           secret=current_user.totp_secret)


 
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
        return redirect(url_for('main.profile'))

    user_id = request.form.get("user_id")
    
    if not user_id:
        flash("Please select a user to share with.", "danger")
        return redirect(url_for('main.profile'))
    
    try:
        user_id = int(user_id)
        user = User.query.get(user_id)
    except (ValueError, TypeError):
        flash("Invalid user selection.", "danger")
        return redirect(url_for('main.profile'))

    if not user:
        flash("User not found!", "danger")
        return redirect(url_for('main.profile'))

    existing_share = SharedNote.query.filter_by(note_id=note.id, user_id=user.id).first()
    if existing_share:
        flash(f"Note already shared with {user.username}.", "info")
    else:
        shared_note = SharedNote(note_id=note.id, user_id=user.id)
        db.session.add(shared_note)
        db.session.commit()
        flash(f"Note shared successfully with {user.username}!", "success")

    return redirect(url_for('main.profile'))

@main.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    form = PasswordResetRequestForm()   
    
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        
        if user:
            try:
                serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
                token = serializer.dumps({'user_id': user.id}, salt='password-reset')
                 
                reset_url = url_for('main.reset_password', token=token, _external=True, _scheme='https')
                
                from flask_mail import Message
                msg = Message(
                    'Password Reset Request',
                    sender=current_app.config['MAIL_DEFAULT_SENDER'],
                    recipients=[email]
                )
                msg.body = f'Hello {user.username},\n\nClick to reset your password: {reset_url}\n\nThis link will expire in 1 hour.\n\nIf you didn\'t request this, ignore this email.'
                mail.send(msg)
                
                flash('Password reset link sent to your email.', 'info')
                return redirect(url_for('main.login'))
                
            except Exception as e:
                current_app.logger.error(f"Error sending reset email: {str(e)}")
                flash('Error sending reset email. Please try again.', 'danger')
        else:
            flash('If that email is registered, you will receive a reset link.', 'info')
    
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

        form = PasswordResetForm()
        
        if form.validate_on_submit():
            password = form.password.data
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

@main.route('/health')
def health_check():
    return jsonify({"status": "healthy"}), 200