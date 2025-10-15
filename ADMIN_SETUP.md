# Admin Setup Guide

## Admin User Creation

An admin user has been created with the following credentials:

- **Username:** `admin`
- **Email:** `Watchman0809@proton.me`
- **Password:** `TOC8925!`
- **Role:** `super_admin` (full capabilities)

## Starting the Application

### 1. Start the Backend API Server

```bash
cd /path/to/passive-osint-suite
python3 api/api_server.py
```

The API will start on `http://localhost:8000`

### 2. Start the Web Interface

```bash
cd web
npm install  # First time only
npm run dev
```

The web interface will start on `http://localhost:3000`

## Using the Web Interface

### Login

1. Click the **Login** button in the top-right corner of the header
2. Enter your credentials:
   - Username: `admin`
   - Password: `TOC8925!`
3. Click **Login**

Once logged in, you'll see your username in the header and have access to all features.

### Settings

Click the **Settings** (gear icon) button in the header to configure:

- **System Configuration:**
  - Max Concurrent Operations
  - Data Retention period
  - Report Storage Path
  - Auto-save toggle

- **API Configuration:**
  - View and update API keys for external services
  - Check API status and last usage times

### Running Domain Investigations

1. Navigate to **OSINT Modules** from the sidebar
2. Find the **Domain Intelligence** card
3. Click **Run Module**
4. In the modal:
   - Enter the domain name (e.g., `example.com`)
   - Select investigation options:
     - DNS Lookup
     - WHOIS Lookup
     - Subdomain Discovery
5. Click **Run Investigation**

## Creating Additional Users

You can create additional users by running the admin user creation script with modifications:

```bash
cd /path/to/passive-osint-suite
python3 create_admin_user.py
```

Or use the backend API endpoint (when authenticated as admin):

```bash
curl -X POST http://localhost:8000/users \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser",
    "password": "SecurePassword123!",
    "email": "user@example.com",
    "full_name": "New User",
    "role": "analyst"
  }'
```

## Available Roles

- **super_admin:** Full system access, can manage users and all resources
- **admin:** Administrative access to most features
- **analyst:** Can run investigations and view results
- **viewer:** Read-only access

## Features Implemented

✅ **Authentication System:**
   - Login modal with username/password
   - JWT token-based authentication
   - Logout functionality
   - Session management with localStorage

✅ **Settings Panel:**
   - System configuration options
   - API key management
   - Configurable investigation parameters

✅ **Domain Investigation Module:**
   - Interactive modal for domain input
   - Multiple investigation options
   - Real-time validation
   - Integration with backend API

✅ **Admin User:**
   - Pre-created admin account
   - Full system capabilities
   - Secure password hashing with bcrypt

## Troubleshooting

### API Connection Issues

If you see "API Offline" in the header:

1. Make sure the backend API server is running on port 8000
2. Check that there are no firewall restrictions
3. Verify the API URL in `web/.env` or `web/vite.config.ts`

### Login Issues

If login fails:

1. Verify the backend API is running
2. Check that the admin user was created successfully
3. Ensure the password is entered correctly (it's case-sensitive)

### Database Connection

The system uses PostgreSQL by default, but falls back to mock mode if the database is unavailable. For production use, ensure PostgreSQL is installed and configured:

```bash
# Install PostgreSQL
sudo apt-get install postgresql postgresql-contrib

# Initialize the database
psql -U postgres -f database/init_postgres.sql
```

## Security Notes

- The JWT secret should be changed in production (see `security/security_api.py`)
- Passwords are hashed using bcrypt before storage
- All API endpoints require authentication except `/auth/login`
- Admin credentials should be changed after initial setup
