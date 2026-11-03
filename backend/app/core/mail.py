"""
ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway
SMTP Mailer Service for Self-Service Password Resets and Regulatory Alerts.
Zero external dependencies: uses standard library smtplib and email.mime.
"""

import logging
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger("regubom.mail")

SMTP_ENABLED = os.environ.get("SMTP_ENABLED", "false").lower() in ("true", "1", "yes")
SMTP_HOST = os.environ.get("SMTP_HOST", "localhost")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM_EMAIL = os.environ.get("SMTP_FROM_EMAIL", "no-reply@regubom.internal")
SMTP_FROM_NAME = os.environ.get("SMTP_FROM_NAME", "ReguBOM Regulatory Gateway")
SMTP_STARTTLS = os.environ.get("SMTP_STARTTLS", "true").lower() in ("true", "1", "yes")
FRONTEND_BASE_URL = os.environ.get("FRONTEND_BASE_URL", "http://localhost:5173").rstrip("/")


def is_smtp_configured() -> bool:
    """Check if SMTP outgoing mailer is enabled and configured."""
    return SMTP_ENABLED and bool(SMTP_HOST.strip())


def send_password_reset_email(to_email: str, username: str, reset_token: str) -> bool:
    """
    Sends a self-service password reset email with the one-time cryptographically secure token.
    Gracefully handles connection timeouts and errors without blocking API callers.
    """
    reset_url = f"{FRONTEND_BASE_URL}/reset-password?token={reset_token}"

    if not is_smtp_configured():
        logger.info(
            f"[SMTP Simulated] Mailer is not enabled. Reset token for user '{username}' ({to_email}): {reset_url}"
        )
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "ReguBOM — Password Reset Request"
        msg["From"] = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>"
        msg["To"] = to_email

        text_content = f"""
Hello {username},

A password reset request was submitted for your ReguBOM account.
To choose a new password, click the link below (valid for 15 minutes):

{reset_url}

If you did not request this change, please ignore this email or notify your system administrator.

ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway
"""

        html_content = f"""
<!DOCTYPE html>
<html>
<head>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f8fafc; color: #1e293b; padding: 24px; }}
    .card {{ background-color: #ffffff; max-width: 540px; margin: 0 auto; padding: 32px; border-radius: 8px; border: 1px solid #e2e8f0; }}
    .header {{ font-size: 18px; font-weight: 700; color: #0f172a; margin-bottom: 16px; border-bottom: 2px solid #2563eb; padding-bottom: 8px; }}
    .button {{ display: inline-block; background-color: #2563eb; color: #ffffff !important; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: 600; margin: 20px 0; }}
    .footer {{ font-size: 11px; color: #64748b; margin-top: 24px; border-top: 1px solid #e2e8f0; padding-top: 12px; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="header">🛡️ ReguBOM Gateway — Password Reset</div>
    <p>Hello <strong>{username}</strong>,</p>
    <p>A request was received to reset your password. Click the secure link below to proceed:</p>
    <p style="text-align: center;">
      <a href="{reset_url}" class="button">Reset Your Password</a>
    </p>
    <p style="font-size: 12px; color: #64748b;">This link is valid for <strong>15 minutes</strong>. If you did not initiate this request, you can safely disregard this notice.</p>
    <div class="footer">
      ReguBOM — Compliant with EU CRA Art. 13 and ENISA Technical Advisory 2026.
    </div>
  </div>
</body>
</html>
"""
        msg.attach(MIMEText(text_content, "plain"))
        msg.attach(MIMEText(html_content, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=5) as server:
            if SMTP_STARTTLS:
                server.starttls()
            if SMTP_USER and SMTP_PASSWORD:
                server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)

        logger.info(f"[SMTP] Successfully sent password reset email to '{to_email}'")
        return True
    except Exception as e:
        logger.error(f"[SMTP] Failed to send password reset email to '{to_email}': {e}")
        return False
