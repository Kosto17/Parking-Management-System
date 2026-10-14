# Parking Management System

## 1. Project Overview

The Parking Management System is a Python-based desktop application developed as a college project for Fundamentals of Total Quality Management (TQM). It manages parking slots, vehicle entry and exit, user accounts, and parking availability, with a focus on security and data accuracy.

## 2. Project Objectives

- Manage parking slots efficiently.
- Track vehicle entry and exit.
- Improve application security.
- Prevent invalid and duplicate entries.
- Record important user activities.
- Provide role-based access to application features.

## 3. Features

### User Authentication
- Login with a username and password.
- Role-based access for Admin, Staff, and User.
- Self-registration for new users.
- Password hashing.
- Password reset by Admin.

### Parking Management
- 50 fixed parking slots.
- Available, Occupied, and Unavailable statuses.
- Parking availability displayed on the dashboard.
- Authorized users can manage parking availability.

### Vehicle Management
- Record vehicle entry and exit.
- Assign available parking slots.
- Validate vehicle details.
- Prevent duplicate active parking entries.

### User Management and Notifications
- Admin can manage user accounts.
- New self-registrations generate notifications for Admin.
- Access depends on the user's role.

### Audit Trail
- Record important activities such as login and account changes.
- Display user IDs, usernames, roles, actions, and timestamps.
- Filter audit records by date.
- Admin-only audit-log deletion.

### Input Validation
- Validate usernames and passwords.
- Check required fields.
- Validate vehicle registration numbers.
- Prevent invalid parking operations.

## 4. User Roles

| Role | Responsibilities |
|---|---|
| Admin | Manage users, view notifications, access audit logs, and manage application functions. |
| Staff | Handle parking operations and manage parking availability as permitted. |
| User | Use the parking and vehicle entry/exit functions permitted by the application. |

## 5. Technologies Used

- Python
- Tkinter and ttk
- SQLite
- Git and GitHub

## 6. Project Structure

```text
Parking-Management-System/
├── main.py
├── database.py
├── .gitignore
└── README.md
```

The local `parking.db` database is excluded from Git tracking.

## 7. Requirements

- Python 3.x
- Tkinter support
- Git (for version control)

## 8. Run the Application

1. Install Python 3.x.
2. Download or clone this repository.
3. Open a terminal in the project folder.
4. Run:

```bash
python main.py
```

The application uses SQLite for local database storage.

## 9. Security and Quality Focus

This project focuses on the TQM quality goal of improving security. Security-related measures include role-based access, password hashing, input validation, audit logging, and account management.

Password hashing is different from reversible encryption. Any additional encryption requirement should be verified separately.

## 10. TQM Tools

The project can be documented and evaluated using:

- FMEA and Risk Priority Number (RPN)
- SIPOC analysis
- Critical to Quality (CTQ) Tree
- Defect logging
- Pareto analysis
- Fishbone diagram
- Checksheet
- PDCA cycle

## 11. Project Status

The application is under development. Further testing and verification are required to confirm that all features work correctly together.

## 12. Repository

https://github.com/Kosto17/Parking-Management-System
