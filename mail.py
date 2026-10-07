import smtplib
from email.message import EmailMessage
import os
from dotenv import load_dotenv

load_dotenv()

SMTP_EMAIL = os.getenv("SMTP_EMAIL")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

def send_email(receiver_email, otp):

    message = EmailMessage()

    message["Subject"] = "VEZORA Password Reset OTP"
    message["From"] = SMTP_EMAIL
    message["To"] = receiver_email

    message.set_content(
        f"""
Hello,

Your VEZORA password reset OTP is:

{otp}

This OTP is valid for this password reset request.

If you did not request a password reset, please ignore this email.

Regards,
VEZORA Team
"""
    )

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:

        server.login(
            SMTP_EMAIL,
            SMTP_PASSWORD
        )

        server.send_message(message)