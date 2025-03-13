from flask import Blueprint, render_template, request, redirect, url_for, flash, session 
from app.models import Note, User, SharedNote
from app import db
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
import hashlib 
import pyotp
from flask import jsonify

import markdown
import pyqrcode
from io import BytesIO
import base64
import re
import os
from werkzeug.utils import secure_filename  
from app.PasswordManager import LoginAttemptTracker, PasswordManager


main = Blueprint('main', __name__)\

def generate_signature(user_id, content):
    data = f"{user_id}:{content}"
    return hashlib.sha256(data.encode()).hexdigest()
 
def verify_signature(note):
    expected_signature = generate_signature(note.user_id, note.content_md)
    return expected_signature == note.signature


@main.route("/")  
@main.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.profile'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Kontrola liczby prób logowania
        if not LoginAttemptTracker.is_login_allowed(username):
            flash('Zbyt wiele nieudanych prób. Spróbuj ponownie później.', 'danger')
            return redirect(url_for('main.login'))
        
        user = User.query.filter_by(username=username).first()
        
        if user:
            # Weryfikacja hasła z wielowarstwowym mechanizmem bezpieczeństwa
            if PasswordManager.verify_password(user.password_hash, password):
                # Reset licznika nieudanych prób
                LoginAttemptTracker.reset_login_attempts(username)
                
                # Resetowanie 2FA
                user.is_2fa_verified = False
                db.session.commit()

                login_user(user)
                
                # Redirect to 2FA if required
                if user.totp_secret:
                    return redirect(url_for('main.verify_2fa'))
                
                return redirect(url_for('main.profile'))
            else:
                # Rejestracja nieudanej próby logowania
                LoginAttemptTracker.record_failed_attempt(username)
                
        # Ogólny, nieprecyzyjny komunikat o błędzie
        flash('Nieprawidłowe dane logowania', 'danger')
    
    return render_template('login.html')



@main.route('/profile')
@login_required
def profile():
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
    # Convert markdown to HTML for each note
    for note in notes:
        if note.content_md:  # Ensure there is content
            note.content_html = markdown.markdown(note.content_md)  # Convert markdown to HTML
        else:
            note.content_html = ""
    return render_template("notes.html", notes=notes)



@main.route('/note/<int:note_id>', methods=['GET', 'POST'])
@login_required
def view_note(note_id):
    note = Note.query.get_or_404(note_id)

    # Sprawdzenie dostępu
    if not note.is_accessible_by(current_user):
        flash("Nie masz dostępu do tej notatki!", "danger")
        return redirect(url_for("main.list_notes"))

    if note.encrypted:
        if request.method == "POST":
            password = request.form["password"]
            decrypted_content = note.decrypt_content(password)

            if decrypted_content:
                content_html = markdown.markdown(decrypted_content)
                return render_template("note.html", note=note, content=content_html)
            else:
                flash("Błędne hasło.", "danger")

        return render_template("note.html", note=note)

    note.content_html = markdown.markdown(note.content_md)
    return render_template("note.html", note=note, content=note.content_html)


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
    if request.method == 'POST':
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
        title = request.form["title"]
        content_md = request.form["content_md"]
        password = request.form.get('password')
        is_public = request.form.get('is_public') == 'true'  # New field for public/private
        
        signature = generate_signature(current_user.id, content_md)

        new_note = Note(
            title=title, 
            content_md=content_md, 
            user_id=current_user.id,
            signature=signature,
            is_public=is_public  # Set the public status
        )

        if password:
            new_note.encrypt_content(password)
        
        db.session.add(new_note)
        db.session.commit()
        
        flash('Note added successfully!', 'success')
        return redirect(url_for('main.profile'))

    return render_template("add_note.html")


@main.route('/verify_2fa', methods=['GET', 'POST'])
@login_required  # Ensure only logged-in users can access
def verify_2fa():
    if request.method == 'POST':
        otp = request.form.get('otp')
        if not otp:
            flash("Please enter the OTP code.", "error")
            return redirect(url_for('main.verify_2fa'))

        totp = pyotp.TOTP(current_user.totp_secret)
        
        if totp.verify(otp):
            current_user.is_2fa_verified = True
            db.session.commit()
            flash("2FA verification successful!", "success")
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


@main.route('/health')
def health_check():
    return jsonify({"status": "healthy"}), 200