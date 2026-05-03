# HostelCare - Student Hostel Complaint System

A Flask + SQLite web app for hostel complaint management with student and admin panels.

## Features

- Student signup and login
- Separate admin login panel
- bcrypt password hashing
- Complaint categories: Electrical, Plumbing, Cleaning, WiFi
- Priority levels: Low, Medium, High
- Image proof upload
- Auto-generated complaint IDs
- In-app notifications
- Admin dashboard with counts, search, and filters
- Student complaint history with status timeline
- Admin notes, student replies, and comments
- Student rating after complaint resolution

## Run

```bash
python -m pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

## Default Admin

- Email: `admin@hostel.com`
- Password: `admin123`

The database file `hostel_complaints.db` is created automatically on first run.
