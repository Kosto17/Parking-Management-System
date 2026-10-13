import sqlite3

# Connect to the database
connection = sqlite3.connect("parking.db")

# Create cursor
cursor = connection.cursor()

# Create users table
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL
)
""")

# Create parking slots table
cursor.execute("""
CREATE TABLE IF NOT EXISTS parking_slots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slot_number TEXT UNIQUE NOT NULL,
    status TEXT NOT NULL
)
""")

# Create vehicles table
cursor.execute("""
CREATE TABLE IF NOT EXISTS vehicles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vehicle_number TEXT NOT NULL,
    owner_name TEXT NOT NULL,
    vehicle_type TEXT NOT NULL,
    slot_number TEXT NOT NULL,
    entry_time TEXT NOT NULL,
    exit_time TEXT
)
""")

# Create audit logs table
cursor.execute("""
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    action TEXT NOT NULL,
    timestamp TEXT NOT NULL
)
""")

connection.commit()
connection.close()

print("Database created successfully!")



# Create default admin user
connection = sqlite3.connect("parking.db")
cursor = connection.cursor()

cursor.execute("""
INSERT OR IGNORE INTO users (username, password, role)
VALUES (?, ?, ?)
""", ("admin", "admin123", "Admin"))

connection.commit()
connection.close()

print("Admin user created!")
