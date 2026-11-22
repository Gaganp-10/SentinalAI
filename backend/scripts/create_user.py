#!/usr/bin/env python3
"""
SentinelAI Administrative CLI: Create User Account

Usage:
  Interactive mode (prompts for password securely without echoing):
    python -m backend.scripts.create_user --username admin --email admin@example.com

  Fully interactive:
    python -m backend.scripts.create_user
"""

import sys
import getpass
import argparse
import re
from typing import Optional

from backend.database.session import SessionLocal
from backend.models.models import User
from backend.utils.security import get_password_hash


def create_user_account(
    username: Optional[str] = None,
    email: Optional[str] = None,
    password: Optional[str] = None,
    db_session=None
) -> None:
    # 1. Prompt for username if missing
    if not username:
        username = input("Enter username: ").strip()
    if not username:
        print("ERROR: Username cannot be empty.", file=sys.stderr)
        sys.exit(1)

    # 2. Prompt for email if missing
    if not email:
        email = input("Enter email address: ").strip()
    if not email or "@" not in email:
        print("ERROR: A valid email address is required.", file=sys.stderr)
        sys.exit(1)

    # 3. Prompt for password securely via getpass if not provided
    if not password:
        password = getpass.getpass("Enter password (min 8 chars): ")
        if len(password) < 8:
            print("ERROR: Password must be at least 8 characters long.", file=sys.stderr)
            sys.exit(1)
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("ERROR: Passwords do not match.", file=sys.stderr)
            sys.exit(1)
    else:
        if len(password) < 8:
            print("ERROR: Password must be at least 8 characters long.", file=sys.stderr)
            sys.exit(1)

    db = db_session if db_session is not None else SessionLocal()
    try:
        norm_username = username.strip()
        norm_email = email.strip().lower()

        # Check existing
        if db.query(User).filter(User.username == norm_username).first():
            print(f"ERROR: User with username '{norm_username}' already exists.", file=sys.stderr)
            sys.exit(1)

        if db.query(User).filter(User.email == norm_email).first():
            print(f"ERROR: User with email '{norm_email}' already exists.", file=sys.stderr)
            sys.exit(1)

        hashed = get_password_hash(password)
        new_user = User(
            username=norm_username,
            email=norm_email,
            hashed_password=hashed,
            is_active=True
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        print(f"SUCCESS: Created user '{norm_username}' (ID: {new_user.id}, Email: {norm_email}) successfully.")
    except Exception as e:
        db.rollback()
        print(f"ERROR: Failed to create user: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        if db_session is None:
            db.close()


def main():
    parser = argparse.ArgumentParser(description="SentinelAI CLI - Create User Account")
    parser.add_argument("--username", "-u", help="Username for the new account")
    parser.add_argument("--email", "-e", help="Email for the new account")
    parser.add_argument("--password", "-p", help="Password (optional, prompts securely if omitted)")

    args = parser.parse_args()
    create_user_account(args.username, args.email, args.password)


if __name__ == "__main__":
    main()

