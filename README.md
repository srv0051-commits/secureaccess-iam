# SecureAccess IAM System

Role-Based Access Control (RBAC) system built with Flask and SQLite.

## Features

- Authentication with password hashing
- Account lockout after failed attempts
- Role-Based Access Control (Admin, HR, Finance, Employee)
- User management
- Audit logging
- Messaging system
- Role-specific dashboards
- Delete user permissions
- Profile images based on roles

## Technologies

- Python
- Flask
- SQLite
- HTML/CSS
- Flask-Bcrypt

## Installation

pip install -r requirements.txt

python seed_admin.py

python app.py