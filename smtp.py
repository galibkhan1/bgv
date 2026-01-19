import smtplib
import socket
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime


Testing = True

def send_email(receiver_email, otp):
    msg = MIMEMultipart()
    msg["From"] = 'hrautomation@wiom.in'
    msg["To"] = receiver_email
    msg["Subject"] = "Your Verification Code"

    if Testing:
        print(f"Testing mode: Email to {receiver_email} with OTP {otp} not sent.")
        return {
            "status": 200,
            "message": "✅ OTP sent successfully! (Testing mode)"
        }

    body = f"Hi,\n\nThis is your verification code {otp}.\n\nThanks"
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(msg["From"], receiver_email, msg.as_string())

        return {
            "status": 200,
            "message": "✅ OTP sent successfully!"
        }

    # 🔐 Authentication issues
    except smtplib.SMTPAuthenticationError:
        return {
            "status": 401,
            "message": "❌ Authentication failed. Please check SMTP username/password or use an App Password."
        }

    # ❌ Email rejected by server
    except smtplib.SMTPRecipientsRefused:
        return {
            "status": 400,
            "message": "❌ Invalid recipient email address."
        }

    # 📭 Sender address rejected
    except smtplib.SMTPSenderRefused:
        return {
            "status": 400,
            "message": "❌ Sender email address rejected by server."
        }

    # 🚫 SMTP command failed
    except smtplib.SMTPDataError:
        return {
            "status": 500,
            "message": "❌ SMTP server rejected the email content."
        }

    # 🌐 Network / connection issues
    except (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected, socket.timeout):
        return {
            "status": 503,
            "message": "❌ Unable to connect to email server. Please try again later."
        }

    # ⚠️ Any other SMTP-related error
    except smtplib.SMTPException as e:
        return {
            "status": 500,
            "message": f"❌ SMTP error occurred: {str(e)}"
        }

    # 💥 Unknown error
    except Exception as e:
        return {
            "status": 500,
            "message": f"❌ Unexpected error occurred: {str(e)}"
        }


def send_completion_email_to_user(receiver_email, user_name):
    """Send verification completion email to user"""
    msg = MIMEMultipart()
    msg["From"] = 'hrautomation@wiom.in'
    msg["To"] = receiver_email
    msg["Subject"] = "✅ Background Verification Completed - DocuCheck"

    if Testing:
        print(f"Testing mode: Completion email to {receiver_email} not sent.")
        return {
            "status": 200,
            "message": "✅ Completion email sent successfully! (Testing mode)"
        }

    body = f"""
Hi {user_name},

Congratulations! 🎉

You have successfully completed all the steps of the background verification process.

✅ PAN Verification - Completed
✅ Aadhaar Verification - Completed
✅ Document Upload - Completed
✅ Bank Account Verification - Completed

Next Steps:
Please complete the employee details form to finalize your onboarding process.

If you have any questions, please contact our HR team.

Best Regards,
DocuCheck Team
hrautomation@wiom.in
"""
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(msg["From"], receiver_email, msg.as_string())

        return {
            "status": 200,
            "message": "✅ Completion email sent successfully!"
        }

    except Exception as e:
        return {
            "status": 500,
            "message": f"❌ Failed to send completion email: {str(e)}"
        }


def send_completion_email_to_company(user_email, user_name, company_email="hrautomation@wiom.in"):
    """Send notification to company about user completion"""
    msg = MIMEMultipart()
    msg["From"] = 'hrautomation@wiom.in'
    msg["To"] = company_email
    msg["Subject"] = f"New Verification Completed - {user_name}"

    if Testing:
        print(f"Testing mode: Company notification email to {company_email} not sent.")
        return {
            "status": 200,
            "message": "✅ Company notification sent successfully! (Testing mode)"
        }

    body = f"""
Hi HR Team,

A new user has completed the background verification process:

User Details:
- Name: {user_name}
- Email: {user_email}
- Completion Date: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}

Verification Status:
✅ PAN Verification - Completed
✅ Aadhaar Verification - Completed
✅ Document Upload - Completed
✅ Bank Account Verification - Completed

The user is now ready to complete the employee details form.

Please review the verification data in the DocuCheck portal.

Best Regards,
DocuCheck System
"""
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(msg["From"], company_email, msg.as_string())

        return {
            "status": 200,
            "message": "✅ Company notification sent successfully!"
        }

    except Exception as e:
        return {
            "status": 500,
            "message": f"❌ Failed to send company notification: {str(e)}"
        }