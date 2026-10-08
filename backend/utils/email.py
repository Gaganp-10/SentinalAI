"""
backend/utils/email.py
======================
Thin email-sending module for the password-reset flow.

Two backends are supported, controlled by settings.EMAIL_BACKEND:

  "console"
      Logs the reset link at INFO level so the flow can be demonstrated
      without any SMTP configuration.
      ONLY available when settings.ENV == "development".
      In any other environment, a WARNING is logged instead and the link
      is NOT printed.

  "smtp"
      Sends a real email via STARTTLS (when settings.SMTP_USE_TLS is
      True) using only stdlib smtplib + email.message.  A 10-second
      timeout is applied to every SMTP operation so a slow mail server
      never blocks the process.

Callers should schedule send_password_reset_email() as a FastAPI
BackgroundTask so the HTTP response time is independent of the mail
server.

Failure policy:
  Any exception from the SMTP backend is caught and logged at ERROR
  level WITHOUT including the token or password.  The error is never
  surfaced to the HTTP caller.
"""

import logging
import smtplib
import traceback
from email.message import EmailMessage

from backend.utils.config import settings

logger = logging.getLogger(__name__)

_SMTP_TIMEOUT_S = 10  # seconds per SMTP network operation


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def send_password_reset_email(to_address: str, reset_link: str) -> None:
    """
    Send a password-reset email to *to_address*.

    This is meant to be called from a FastAPI BackgroundTask.  All
    exceptions are swallowed so that a broken mail configuration never
    leaks an error to the end user.

    The *reset_link* contains the raw (unhashed) token in the query
    string.  It is NEVER written to any log except in the dev-mode
    console backend (see module docstring).
    """
    expire_minutes = settings.PASSWORD_RESET_EXPIRE_MINUTES

    subject = "Reset your SentinelAI password"

    plain_body = (
        f"Hello,\n\n"
        f"We received a request to reset the password for your SentinelAI account.\n\n"
        f"Click the link below to set a new password.  The link expires in "
        f"{expire_minutes} minute{'s' if expire_minutes != 1 else ''}:\n\n"
        f"  {reset_link}\n\n"
        f"If you did not request a password reset, you can safely ignore this message. "
        f"Your account remains secure and no changes have been made.\n\n"
        f"Note: if you signed up with Google, using this link will add an email and "
        f"password login option to your account — both login methods will then work.\n\n"
        f"— The SentinelAI team"
    )

    html_body = f"""\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="referrer" content="no-referrer"></head>
<body style="font-family:sans-serif;color:#1a1a1a;background:#f5f5f5;margin:0;padding:0;">
  <table width="100%" cellpadding="0" cellspacing="0">
    <tr><td align="center" style="padding:40px 16px;">
      <table width="480" cellpadding="0" cellspacing="0"
             style="background:#fff;border-radius:12px;padding:36px 32px;
                    box-shadow:0 2px 8px rgba(0,0,0,.08);">
        <tr><td>
          <h2 style="margin:0 0 16px;font-size:20px;">Reset your SentinelAI password</h2>
          <p style="margin:0 0 16px;line-height:1.6;">
            We received a request to reset the password on your account.
            Click the button below to set a new password.
            The link expires in
            <strong>{expire_minutes} minute{'s' if expire_minutes != 1 else ''}</strong>.
          </p>
          <p style="text-align:center;margin:28px 0;">
            <a href="{reset_link}"
               style="display:inline-block;padding:12px 28px;background:#1a1a1a;
                      color:#fff;text-decoration:none;border-radius:8px;font-weight:600;">
              Reset Password
            </a>
          </p>
          <p style="margin:0 0 16px;line-height:1.6;font-size:13px;color:#555;">
            If you did not request this, you can safely ignore this message.
            Your account is unchanged.
          </p>
          <p style="margin:0;line-height:1.6;font-size:13px;color:#555;">
            <em>Note: if you signed up with Google, this link will also add an
            email&thinsp;+&thinsp;password login option to your account.</em>
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>
"""

    backend = settings.EMAIL_BACKEND.lower()

    if backend == "console":
        _send_console(to_address, reset_link)
    elif backend == "smtp":
        _send_smtp(to_address, subject, plain_body, html_body)
    else:
        logger.warning(
            "Unknown EMAIL_BACKEND %r. Password reset email to %s was NOT sent.",
            backend,
            to_address,
        )


# ---------------------------------------------------------------------------
# Backend implementations
# ---------------------------------------------------------------------------

def _send_console(to_address: str, reset_link: str) -> None:
    """
    Log the reset link to stdout (INFO level) for local development only.

    The console backend is disabled in any environment other than
    "development" to prevent token leakage through log aggregators in
    staging or production.
    """
    if settings.ENV.lower() != "development":
        logger.warning(
            "Password reset requested for %s but email is not configured "
            "(EMAIL_BACKEND=console is only allowed in development). "
            "The reset link has NOT been logged.",
            to_address,
        )
        return

    logger.info(
        "\n"
        "======================================================\n"
        "  [DEV] Password reset link for %s\n"
        "  %s\n"
        "  (expires in %d minutes)\n"
        "======================================================",
        to_address,
        reset_link,
        settings.PASSWORD_RESET_EXPIRE_MINUTES,
    )


def _send_smtp(
    to_address: str,
    subject: str,
    plain_body: str,
    html_body: str,
) -> None:
    """
    Send a multi-part (plain text + HTML) email via STARTTLS SMTP.

    The SMTP connection uses a 10-second timeout on every network
    operation.  Any failure is logged at ERROR level WITHOUT including
    the token.
    """
    from_addr = settings.SMTP_FROM or settings.SMTP_USER
    if not from_addr:
        logger.error(
            "SMTP_FROM and SMTP_USER are both empty; cannot send password reset email. "
            "Configure SMTP settings in .env."
        )
        return

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_address
    # Discourage referrer leakage at the header level as well
    msg["Referrer-Policy"] = "no-referrer"

    # Plain text is the primary content; HTML is an alternative
    msg.set_content(plain_body)
    msg.add_alternative(html_body, subtype="html")

    try:
        if settings.SMTP_USE_TLS:
            # STARTTLS (port 587)
            with smtplib.SMTP(
                settings.SMTP_HOST, settings.SMTP_PORT, timeout=_SMTP_TIMEOUT_S
            ) as smtp:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
                if settings.SMTP_USER and settings.SMTP_PASSWORD:
                    smtp.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                smtp.send_message(msg)
        else:
            # Plain SMTP (or implicit TLS via smtplib.SMTP_SSL)
            with smtplib.SMTP_SSL(
                settings.SMTP_HOST, settings.SMTP_PORT, timeout=_SMTP_TIMEOUT_S
            ) as smtp:
                if settings.SMTP_USER and settings.SMTP_PASSWORD:
                    smtp.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                smtp.send_message(msg)

        logger.info("Password reset email sent to %s", to_address)

    except Exception:  # noqa: BLE001
        # Log the error WITHOUT the token or reset link.
        logger.error(
            "Failed to send password reset email to %s: %s",
            to_address,
            traceback.format_exc().splitlines()[-1],  # last line only, no token
        )
