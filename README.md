# PentReport

PentReport is a web-based application designed to streamline the penetration testing reporting process. It provides a centralized platform for managing clients, reports, and vulnerabilities, allowing security professionals to create, track, and export professional-looking PDF reports.

## Features

- **Client Management:** Add, edit, and manage client information.
- **Report Management:** Create, edit, and track penetration testing reports.
- **Vulnerability Management:** Add, edit, and track vulnerabilities, including their severity, status, and description.
- **Dashboard:** View key statistics at a glance, such as the number of open vulnerabilities, recent reports, and reports by status.
- **PDF Export:** Generate professional PDF reports for clients.
- **User Authentication:** Secure access to the application with user accounts and roles.

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/seu-usuario/pentreport.git
   cd pentreport
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
   **Note:** `weasyprint` requires system libraries. On Debian-based systems, install them with:
   ```bash
   sudo apt install libpango-1.0-0 libpangocairo-1.0-0 libcairo2
   ```

4. **Configure the application:**
   - Copy the `.env.example` file to `.env`:
     ```bash
     cp .env.example .env
     ```
   - Edit the `.env` file and set the database connection details and a secret key.

5. **Initialize the database:**
   ```bash
   flask init-db
   ```

6. **Create an admin user:**
   ```bash
   flask create-admin
   ```

## Usage

1. **Start the application:**
   ```bash
   ./start.sh
   ```

2. **Access the application:**
   Open your web browser and go to `http://localhost:5000`.

3. **Log in:**
   Use the admin credentials created during installation (default: `admin`/`admin123`).

## Dependencies

The main dependencies are:

- Flask
- Flask-SQLAlchemy
- Flask-Login
- Flask-WTF
- Flask-Migrate
- PyMySQL
- WeasyPrint

For a complete list of dependencies, see the `requirements.txt` file.
