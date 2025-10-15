#!/usr/bin/env python3
"""
Script to create an admin user for the OSINT Suite
"""

import sys
from security.rbac_manager import rbac_manager
from security.security_database import security_db

def create_admin_user():
    """Create admin user with specified credentials"""
    username = "admin"
    email = "Watchman0809@proton.me"
    password = "TOC8925!"
    full_name = "Admin User"
    role = "super_admin"
    
    try:
        # Check if user already exists
        existing_user = security_db.load_user_by_username(username)
        if existing_user:
            print(f"User '{username}' already exists with ID: {existing_user.id}")
            print(f"Email: {existing_user.email}")
            print(f"Role: {existing_user.roles}")
            return existing_user
        
        # Create the admin user
        user = rbac_manager.create_user(
            username=username,
            password=password,
            email=email,
            full_name=full_name,
            role=role
        )
        
        print(f"✓ Admin user created successfully!")
        print(f"  Username: {username}")
        print(f"  Email: {email}")
        print(f"  Role: {role}")
        print(f"  User ID: {user.id}")
        return user
        
    except Exception as e:
        print(f"✗ Error creating admin user: {e}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    print("Creating admin user for OSINT Suite...")
    user = create_admin_user()
    if user:
        sys.exit(0)
    else:
        sys.exit(1)
