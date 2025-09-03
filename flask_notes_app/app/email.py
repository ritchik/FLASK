from flask_mail import Message
from flask import current_app, render_template
from threading import Thread
from app import mail

def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)

def send_email(to, subject, template, **kwargs):
    msg = Message(
        subject,
        sender=current_app.config['MAIL_DEFAULT_SENDER'],
        recipients=[to]
    )
    msg.html = render_template(template, **kwargs)
    Thread(target=send_async_email, args=(current_app._get_current_object(), msg)).start()