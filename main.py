import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime, timedelta
import sqlite3
import re
import hashlib
import hmac
import os

# ============================================================
# PARKING MANAGEMENT SYSTEM
# UI-focused version:
# - One main application window
# - Responsive dashboard layout
# - Scrollable pages where needed
# - Fixed 50 parking slots
# - Admin / Staff / User roles
# - Password hashing
# - Audit trail
# ============================================================

DB_NAME = os.path.join(os.path.dirname(os.path.abspath(__file__)), "parking.db")
TOTAL_SLOTS = 50

APP_BG = "#f4f6f8"
CARD_BG = "#ffffff"
TEXT = "#1f2937"
MUTED = "#6b7280"
PRIMARY = "#2563eb"
PRIMARY_DARK = "#1d4ed8"
SUCCESS = "#16a34a"
WARNING = "#f59e0b"
DANGER = "#dc2626"
UNAVAILABLE = "#f97316"
BORDER = "#dbe1e8"


# ============================================================
# DATABASE
# ============================================================

def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def setup_database():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS parking_slots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slot_number INTEGER UNIQUE NOT NULL,
            status TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vehicles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vehicle_number TEXT NOT NULL,
            owner_name TEXT NOT NULL,
            vehicle_type TEXT NOT NULL,
            slot_number INTEGER NOT NULL,
            entry_time TEXT NOT NULL,
            exit_time TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT NOT NULL,
            role TEXT,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)

    # Upgrade older audit_logs tables without deleting existing records.
    cursor.execute("PRAGMA table_info(audit_logs)")
    audit_columns = {row[1] for row in cursor.fetchall()}

    if "user_id" not in audit_columns:
        cursor.execute("ALTER TABLE audit_logs ADD COLUMN user_id INTEGER")

    if "role" not in audit_columns:
        cursor.execute("ALTER TABLE audit_logs ADD COLUMN role TEXT")

    # Fill the new actor information for existing records where possible.
    cursor.execute("""
        UPDATE audit_logs
        SET user_id = (
            SELECT id FROM users WHERE users.username = audit_logs.username
        ),
        role = (
            SELECT role FROM users WHERE users.username = audit_logs.username
        )
        WHERE user_id IS NULL OR role IS NULL
    """)

    # Notifications are stored so Admin can see new-user registrations
    # even when the Admin application was not running at that moment.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL,
            read INTEGER NOT NULL DEFAULT 0
        )
    """)

    # Small settings table used only for one-time database migrations.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS app_settings (
            setting_key TEXT PRIMARY KEY,
            setting_value TEXT NOT NULL
        )
    """)

    # Make sure the default administrator exists.
    cursor.execute(
        "SELECT id, password, role FROM users WHERE username=?",
        ("admin",)
    )
    admin_row = cursor.fetchone()

    if admin_row is None:
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("admin", hash_password("admin123"), "Admin")
        )
    else:
        # Always keep the admin role as Admin.
        if admin_row[2] != "Admin":
            cursor.execute(
                "UPDATE users SET role=? WHERE username=?",
                ("Admin", "admin")
            )

        # IMPORTANT:
        # The previous version could leave an existing database with an
        # unknown/old admin password. Perform a ONE-TIME recovery so that
        # admin/admin123 definitely works. After this migration, changing
        # the admin password through User Management will persist normally.
        cursor.execute(
            "SELECT setting_value FROM app_settings WHERE setting_key=?",
            ("admin_default_repair_v1",)
        )
        repaired = cursor.fetchone()

        if repaired is None:
            cursor.execute(
                "UPDATE users SET password=? WHERE username=?",
                (hash_password("admin123"), "admin")
            )
            cursor.execute(
                "INSERT INTO app_settings (setting_key, setting_value) VALUES (?, ?)",
                ("admin_default_repair_v1", "done")
            )

    # If the admin was newly created, mark the migration as completed too.
    cursor.execute(
        "SELECT setting_value FROM app_settings WHERE setting_key=?",
        ("admin_default_repair_v1",)
    )
    if cursor.fetchone() is None:
        cursor.execute(
            "INSERT INTO app_settings (setting_key, setting_value) VALUES (?, ?)",
            ("admin_default_repair_v1", "done")
        )

    conn.commit()
    conn.close()


def initialize_parking_slots():
    """Create missing fixed slots 1-50 without changing existing statuses."""
    conn = get_connection()
    cursor = conn.cursor()

    for slot_number in range(1, TOTAL_SLOTS + 1):
        cursor.execute(
            "SELECT id FROM parking_slots WHERE slot_number=?",
            (slot_number,)
        )
        if cursor.fetchone() is None:
            cursor.execute(
                """
                INSERT INTO parking_slots (slot_number, status)
                VALUES (?, 'Available')
                """,
                (slot_number,)
            )

    conn.commit()
    conn.close()


# ============================================================
# PASSWORD SECURITY
# ============================================================

def hash_password(password):
    """PBKDF2-HMAC-SHA256 salted password hash."""
    salt = os.urandom(16)
    iterations = 200_000
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations
    )
    return f"PBKDF2${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password, stored_password):
    """
    Verify a modern PBKDF2 password.
    Also accepts the old plaintext format so existing accounts
    can be upgraded after a successful login.
    """
    if not stored_password:
        return False, False

    if not stored_password.startswith("PBKDF2$"):
        return hmac.compare_digest(password, stored_password), True

    try:
        _, iterations, salt_hex, digest_hex = stored_password.split("$")
        iterations = int(iterations)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)

        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations
        )

        return hmac.compare_digest(actual, expected), False
    except (ValueError, TypeError):
        return False, False


# ============================================================
# AUDIT
# ============================================================

def create_audit_log(username, action):
    """Store only meaningful security/operational actions.

    The displayed User ID is the ID of the person performing the action,
    so the same user keeps the same ID across all of their audit records.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id, role FROM users WHERE username=?",
        (username,)
    )
    user = cursor.fetchone()

    user_id = user["id"] if user else None
    role = user["role"] if user else None

    cursor.execute(
        """
        INSERT INTO audit_logs (user_id, username, role, action, timestamp)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            user_id,
            username,
            role,
            action,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
    )

    conn.commit()
    conn.close()


# ============================================================
# NOTIFICATIONS
# ============================================================

def create_admin_notification(username, message):
    """Create a notification that can be seen by Admin users."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO notifications
        (username, message, created_at, read)
        VALUES (?, ?, ?, 0)
        """,
        (
            username,
            message,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
    )

    conn.commit()
    conn.close()


def get_unread_notification_count():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM notifications WHERE read=0"
    )
    count = cursor.fetchone()[0]

    conn.close()
    return count


# ============================================================
# VALIDATION
# ============================================================

def validate_username(username):
    if not 3 <= len(username) <= 20:
        return False, "Username must be 3-20 characters."
    if not re.fullmatch(r"[A-Za-z0-9_]+", username):
        return False, "Username can contain only letters, numbers and underscore."
    return True, ""


def validate_password(password):
    if len(password) < 6:
        return False, "Password must be at least 6 characters."
    return True, ""


def validate_slot_number(slot_number):
    if not slot_number.isdigit():
        return False, "Slot number must contain digits only."

    number = int(slot_number)

    if not 1 <= number <= TOTAL_SLOTS:
        return False, f"Slot number must be between 1 and {TOTAL_SLOTS}."

    return True, ""


def validate_vehicle_number(vehicle_number):
    vehicle_number = vehicle_number.upper().replace(" ", "")

    if not re.fullmatch(r"[A-Z]{2}[0-9]{1,2}[A-Z]{1,3}[0-9]{1,4}", vehicle_number):
        return False, "Enter a valid vehicle number, e.g. UK07AB1234."

    return True, ""


def validate_owner_name(owner_name):
    if not re.fullmatch(r"[A-Za-z ]{2,50}", owner_name):
        return False, "Owner name must contain only letters and spaces."
    return True, ""


# ============================================================
# MAIN APPLICATION
# ============================================================

class ParkingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Parking Management System")
        self.root.minsize(1000, 650)

        try:
            self.root.state("zoomed")
        except tk.TclError:
            self.root.geometry("1200x750")

        self.username = None
        self.role = None

        self.colors = {
            "Available": "#dcfce7",
            "Occupied": "#fee2e2",
            "Unavailable": "#ffedd5",
        }

        self.text_colors = {
            "Available": "#166534",
            "Occupied": "#991b1b",
            "Unavailable": "#9a3412",
        }

        self.setup_styles()
        self.show_login()

    # --------------------------------------------------------
    # STYLE
    # --------------------------------------------------------

    def setup_styles(self):
        style = ttk.Style()

        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "App.TFrame",
            background=APP_BG
        )

        style.configure(
            "Card.TFrame",
            background=CARD_BG,
            relief="flat"
        )

        style.configure(
            "Title.TLabel",
            background=APP_BG,
            foreground=TEXT,
            font=("Segoe UI", 24, "bold")
        )

        style.configure(
            "Subtitle.TLabel",
            background=APP_BG,
            foreground=MUTED,
            font=("Segoe UI", 10)
        )

        style.configure(
            "CardTitle.TLabel",
            background=CARD_BG,
            foreground=TEXT,
            font=("Segoe UI", 14, "bold")
        )

        style.configure(
            "Body.TLabel",
            background=CARD_BG,
            foreground=TEXT,
            font=("Segoe UI", 10)
        )

        style.configure(
            "Muted.TLabel",
            background=CARD_BG,
            foreground=MUTED,
            font=("Segoe UI", 9)
        )

        style.configure(
            "Primary.TButton",
            font=("Segoe UI", 10, "bold"),
            padding=(14, 9)
        )

        style.configure(
            "Secondary.TButton",
            font=("Segoe UI", 10),
            padding=(12, 8)
        )

        style.configure(
            "Danger.TButton",
            font=("Segoe UI", 10, "bold"),
            padding=(12, 8)
        )

        style.configure(
            "Treeview",
            rowheight=30,
            font=("Segoe UI", 9)
        )

        style.configure(
            "Treeview.Heading",
            font=("Segoe UI", 9, "bold")
        )

        style.configure(
            "TEntry",
            padding=8
        )

        style.configure(
            "TCombobox",
            padding=7
        )

    # --------------------------------------------------------
    # GENERAL HELPERS
    # --------------------------------------------------------

    def clear_root(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def make_button(self, parent, text, command, style="Secondary.TButton"):
        return ttk.Button(
            parent,
            text=text,
            command=command,
            style=style
        )

    def add_header(self, parent, title, subtitle=""):
        frame = ttk.Frame(parent, style="App.TFrame")
        frame.pack(fill="x", padx=28, pady=(25, 15))

        ttk.Label(
            frame,
            text=title,
            style="Title.TLabel"
        ).pack(anchor="w")

        if subtitle:
            ttk.Label(
                frame,
                text=subtitle,
                style="Subtitle.TLabel"
            ).pack(anchor="w", pady=(4, 0))

        return frame

    def make_card(self, parent, padding=18):
        outer = tk.Frame(
            parent,
            bg=CARD_BG,
            highlightbackground=BORDER,
            highlightthickness=1,
            bd=0
        )
        outer.pack(fill="x", padx=28, pady=8)
        inner = tk.Frame(outer, bg=CARD_BG)
        inner.pack(fill="both", expand=True, padx=padding, pady=padding)
        return inner

    def create_scrollable_page(self, parent):
        outer = tk.Frame(parent, bg=APP_BG)
        outer.pack(fill="both", expand=True)

        canvas = tk.Canvas(
            outer,
            bg=APP_BG,
            highlightthickness=0,
            bd=0
        )
        scrollbar = ttk.Scrollbar(
            outer,
            orient="vertical",
            command=canvas.yview
        )

        content = tk.Frame(canvas, bg=APP_BG)

        window_id = canvas.create_window(
            (0, 0),
            window=content,
            anchor="nw"
        )

        def update_scroll_region(event=None):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def resize_content(event):
            canvas.itemconfigure(window_id, width=event.width)

        content.bind("<Configure>", update_scroll_region)
        canvas.bind("<Configure>", resize_content)
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        def mouse_wheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas.bind_all("<MouseWheel>", mouse_wheel)

        return content

    # --------------------------------------------------------
    # LOGIN
    # --------------------------------------------------------

    def show_login(self):
        self.clear_root()
        self.root.title("Parking Management System - Login")

        main = tk.Frame(self.root, bg=APP_BG)
        main.pack(fill="both", expand=True)

        center = tk.Frame(main, bg=CARD_BG)
        center.place(relx=0.5, rely=0.5, anchor="center", width=460, height=500)

        tk.Label(
            center,
            text="PARKING",
            bg=CARD_BG,
            fg=PRIMARY,
            font=("Segoe UI", 14, "bold")
        ).pack(pady=(45, 0))

        tk.Label(
            center,
            text="Management System",
            bg=CARD_BG,
            fg=TEXT,
            font=("Segoe UI", 25, "bold")
        ).pack(pady=(3, 8))

        tk.Label(
            center,
            text="Secure • Simple • Organized",
            bg=CARD_BG,
            fg=MUTED,
            font=("Segoe UI", 10)
        ).pack(pady=(0, 30))

        form = tk.Frame(center, bg=CARD_BG)
        form.pack(fill="x", padx=55)

        tk.Label(
            form,
            text="Username",
            bg=CARD_BG,
            fg=TEXT,
            font=("Segoe UI", 10, "bold")
        ).pack(anchor="w")

        self.login_username = ttk.Entry(form)
        self.login_username.pack(fill="x", pady=(5, 18))

        tk.Label(
            form,
            text="Password",
            bg=CARD_BG,
            fg=TEXT,
            font=("Segoe UI", 10, "bold")
        ).pack(anchor="w")

        self.login_password = ttk.Entry(form, show="*")
        self.login_password.pack(fill="x", pady=(5, 20))

        self.make_button(
            form,
            "LOGIN",
            self.login,
            "Primary.TButton"
        ).pack(fill="x", pady=5)

        self.make_button(
            form,
            "CREATE NEW USER",
            self.show_register,
            "Secondary.TButton"
        ).pack(fill="x", pady=(2, 5))

        tk.Label(
            center,
            text="Default administrator: admin / admin123",
            bg=CARD_BG,
            fg=MUTED,
            font=("Segoe UI", 8)
        ).pack(side="bottom", pady=22)

        self.login_username.focus_set()
        self.login_password.bind("<Return>", lambda event: self.login())

    def show_register(self):
        """Show self-registration. Every self-created account is a User."""
        self.clear_root()
        self.root.title("Parking Management System - Create New User")

        main = tk.Frame(self.root, bg=APP_BG)
        main.pack(fill="both", expand=True)

        center = tk.Frame(main, bg=CARD_BG)
        center.place(
            relx=0.5,
            rely=0.5,
            anchor="center",
            width=460,
            height=560
        )

        tk.Label(
            center,
            text="CREATE NEW USER",
            bg=CARD_BG,
            fg=PRIMARY,
            font=("Segoe UI", 20, "bold")
        ).pack(pady=(38, 8))

        tk.Label(
            center,
            text="Self-registration creates a standard User account.",
            bg=CARD_BG,
            fg=MUTED,
            font=("Segoe UI", 9)
        ).pack(pady=(0, 25))

        form = tk.Frame(center, bg=CARD_BG)
        form.pack(fill="x", padx=55)

        tk.Label(
            form,
            text="Username",
            bg=CARD_BG,
            fg=TEXT,
            font=("Segoe UI", 10, "bold")
        ).pack(anchor="w")

        username_entry = ttk.Entry(form)
        username_entry.pack(fill="x", pady=(5, 16))

        tk.Label(
            form,
            text="Password",
            bg=CARD_BG,
            fg=TEXT,
            font=("Segoe UI", 10, "bold")
        ).pack(anchor="w")

        password_entry = ttk.Entry(form, show="*")
        password_entry.pack(fill="x", pady=(5, 16))

        tk.Label(
            form,
            text="Confirm Password",
            bg=CARD_BG,
            fg=TEXT,
            font=("Segoe UI", 10, "bold")
        ).pack(anchor="w")

        confirm_entry = ttk.Entry(form, show="*")
        confirm_entry.pack(fill="x", pady=(5, 20))

        def register_user():
            username = username_entry.get().strip()
            password = password_entry.get()
            confirm_password = confirm_entry.get()

            valid, error = validate_username(username)
            if not valid:
                messagebox.showerror(
                    "Invalid Username",
                    error
                )
                return

            valid, error = validate_password(password)
            if not valid:
                messagebox.showerror(
                    "Invalid Password",
                    error
                )
                return

            if password != confirm_password:
                messagebox.showerror(
                    "Password Mismatch",
                    "Password and Confirm Password must match."
                )
                return

            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute(
                "SELECT id FROM users WHERE username=?",
                (username,)
            )

            if cursor.fetchone() is not None:
                conn.close()
                messagebox.showerror(
                    "Username Already Exists",
                    "This username already exists. Please choose another username."
                )
                return

            try:
                cursor.execute(
                    """
                    INSERT INTO users
                    (username, password, role)
                    VALUES (?, ?, ?)
                    """,
                    (
                        username,
                        hash_password(password),
                        "User"
                    )
                )
                conn.commit()
            except sqlite3.IntegrityError:
                conn.close()
                messagebox.showerror(
                    "Registration Failed",
                    "This username already exists. Please choose another username."
                )
                return

            conn.close()

            # Store an Admin notification so it is available even when
            # no Admin application window is currently open.
            create_admin_notification(
                username,
                f"New user registered: {username}"
            )

            # Record the meaningful security/account event.
            create_audit_log(
                username,
                "Self-registered new User account"
            )

            messagebox.showinfo(
                "Account Created",
                "Account created successfully. You can now login."
            )

            self.show_login()

        self.make_button(
            form,
            "CREATE ACCOUNT",
            register_user,
            "Primary.TButton"
        ).pack(fill="x", pady=5)

        self.make_button(
            form,
            "BACK TO LOGIN",
            self.show_login,
            "Secondary.TButton"
        ).pack(fill="x", pady=(2, 5))

        username_entry.focus_set()

    def login(self):
        username = self.login_username.get().strip()
        password = self.login_password.get()

        if not username or not password:
            messagebox.showerror(
                "Login Failed",
                "Please enter username and password."
            )
            return

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT username, password, role
            FROM users
            WHERE username=?
            """,
            (username,)
        )

        user = cursor.fetchone()

        if user is None:
            conn.close()
            messagebox.showerror(
                "Login Failed",
                "Invalid username or password."
            )
            return

        valid, was_plaintext = verify_password(
            password,
            user["password"]
        )

        if not valid:
            conn.close()
            messagebox.showerror(
                "Login Failed",
                "Invalid username or password."
            )
            return

        # Upgrade old plaintext password automatically.
        if was_plaintext:
            cursor.execute(
                """
                UPDATE users
                SET password=?
                WHERE username=?
                """,
                (hash_password(password), username)
            )
            conn.commit()

        conn.close()

        self.username = user["username"]
        self.role = user["role"]

        create_audit_log(
            self.username,
            "Logged in"
        )

        self.show_dashboard()

    # --------------------------------------------------------
    # DASHBOARD
    # --------------------------------------------------------

    def show_dashboard(self):
        self.clear_root()
        self.root.title("Parking Management System")

        main = tk.Frame(self.root, bg=APP_BG)
        main.pack(fill="both", expand=True)

        self.sidebar = tk.Frame(
            main,
            bg="#111827",
            width=285
        )
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        self.content_area = tk.Frame(
            main,
            bg=APP_BG
        )
        self.content_area.pack(
            side="right",
            fill="both",
            expand=True
        )

        self.build_sidebar()
        self.show_home()

    def build_sidebar(self):
        brand = tk.Frame(self.sidebar, bg="#111827")
        brand.pack(fill="x", padx=22, pady=(28, 26))

        tk.Label(
            brand,
            text="PARKING",
            bg="#111827",
            fg="#60a5fa",
            font=("Segoe UI", 14, "bold"),
            anchor="w"
        ).pack(anchor="w")

        tk.Label(
            brand,
            text="MANAGEMENT",
            bg="#111827",
            fg="white",
            font=("Segoe UI", 14, "bold"),
            anchor="w"
        ).pack(anchor="w")

        tk.Label(
            brand,
            text="SYSTEM",
            bg="#111827",
            fg="white",
            font=("Segoe UI", 14, "bold"),
            anchor="w"
        ).pack(anchor="w")

        tk.Label(
            self.sidebar,
            text=f"{self.username}  •  {self.role}",
            bg="#1f2937",
            fg="#d1d5db",
            font=("Segoe UI", 9),
            anchor="w",
            padx=12
        ).pack(fill="x", padx=15, pady=(0, 20), ipady=9)

        self.sidebar_button("Dashboard", self.show_home)
        self.sidebar_button("Parking Slots", self.show_parking_layout)
        self.sidebar_button("Vehicle Entry", self.show_vehicle_entry)
        self.sidebar_button("View Vehicles", self.show_vehicles)
        self.sidebar_button("Vehicle Exit", self.show_vehicle_exit)

        if self.role == "Admin":
            self.sidebar_button("User Management", self.show_user_management)

            unread_count = get_unread_notification_count()
            notification_text = (
                f"Notifications ({unread_count})"
                if unread_count > 0
                else "Notifications"
            )
            self.sidebar_button(
                notification_text,
                self.show_notifications
            )

            self.sidebar_button("Audit Logs", self.show_audit_logs)

        tk.Frame(
            self.sidebar,
            bg="#111827"
        ).pack(fill="both", expand=True)

        logout = tk.Button(
            self.sidebar,
            text="Logout",
            command=self.logout,
            bg="#7f1d1d",
            fg="white",
            activebackground="#991b1b",
            activeforeground="white",
            relief="flat",
            bd=0,
            font=("Segoe UI", 10, "bold"),
            cursor="hand2"
        )
        logout.pack(fill="x", padx=15, pady=18, ipady=9)

    def sidebar_button(self, text, command):
        button = tk.Button(
            self.sidebar,
            text=text,
            command=command,
            bg="#111827",
            fg="#d1d5db",
            activebackground="#1d4ed8",
            activeforeground="white",
            relief="flat",
            bd=0,
            anchor="w",
            padx=25,
            font=("Segoe UI", 10),
            cursor="hand2"
        )
        button.pack(fill="x", pady=1, ipady=8)

    def clear_content(self):
        for widget in self.content_area.winfo_children():
            widget.destroy()

    def logout(self):
        create_audit_log(
            self.username,
            "Logged out"
        )

        self.username = None
        self.role = None
        self.show_login()

    # --------------------------------------------------------
    # HOME
    # --------------------------------------------------------

    def show_home(self):
        self.clear_content()

        self.add_header(
            self.content_area,
            "Dashboard",
            f"Welcome back, {self.username}. You are logged in as {self.role}."
        )

        counts = self.get_slot_counts()

        cards = tk.Frame(
            self.content_area,
            bg=APP_BG
        )
        cards.pack(fill="x", padx=20, pady=5)

        self.stat_card(
            cards,
            "TOTAL SLOTS",
            str(TOTAL_SLOTS),
            PRIMARY
        )
        self.stat_card(
            cards,
            "AVAILABLE",
            str(counts["Available"]),
            SUCCESS
        )
        self.stat_card(
            cards,
            "OCCUPIED",
            str(counts["Occupied"]),
            DANGER
        )
        self.stat_card(
            cards,
            "UNAVAILABLE",
            str(counts["Unavailable"]),
            UNAVAILABLE
        )

        card = self.make_card(self.content_area)

        ttk.Label(
            card,
            text="Quick Actions",
            style="CardTitle.TLabel"
        ).pack(anchor="w")

        ttk.Label(
            card,
            text="Use the options below to manage parking.",
            style="Muted.TLabel"
        ).pack(anchor="w", pady=(3, 15))

        actions = tk.Frame(card, bg=CARD_BG)
        actions.pack(fill="x")

        self.action_button(
            actions,
            "View Parking Layout",
            self.show_parking_layout
        )

        self.action_button(
            actions,
            "Vehicle Entry",
            self.show_vehicle_entry
        )

        self.action_button(
            actions,
            "Vehicle Exit",
            self.show_vehicle_exit
        )

        if self.role == "Admin":
            self.action_button(
                actions,
                "User Management",
                self.show_user_management
            )

    def stat_card(self, parent, title, value, accent):
        card = tk.Frame(
            parent,
            bg=CARD_BG,
            highlightbackground=BORDER,
            highlightthickness=1
        )
        card.pack(
            side="left",
            fill="both",
            expand=True,
            padx=8,
            pady=8
        )

        tk.Frame(
            card,
            bg=accent,
            width=5
        ).pack(side="left", fill="y")

        inner = tk.Frame(card, bg=CARD_BG)
        inner.pack(fill="both", expand=True, padx=18, pady=15)

        tk.Label(
            inner,
            text=title,
            bg=CARD_BG,
            fg=MUTED,
            font=("Segoe UI", 9, "bold")
        ).pack(anchor="w")

        tk.Label(
            inner,
            text=value,
            bg=CARD_BG,
            fg=TEXT,
            font=("Segoe UI", 24, "bold")
        ).pack(anchor="w", pady=(3, 0))

    def action_button(self, parent, text, command):
        self.make_button(
            parent,
            text,
            command,
            "Secondary.TButton"
        ).pack(side="left", padx=(0, 10), pady=5)

    # --------------------------------------------------------
    # SLOT DATA
    # --------------------------------------------------------

    def get_slot_counts(self):
        conn = get_connection()
        cursor = conn.cursor()

        counts = {
            "Available": 0,
            "Occupied": 0,
            "Unavailable": 0
        }

        for slot_number in range(1, TOTAL_SLOTS + 1):
            cursor.execute(
                """
                SELECT status
                FROM parking_slots
                WHERE slot_number=?
                """,
                (slot_number,)
            )

            row = cursor.fetchone()
            status = row["status"] if row else "Available"

            if status not in counts:
                status = "Available"

            counts[status] += 1

        conn.close()
        return counts

    def get_slots(self):
        conn = get_connection()
        cursor = conn.cursor()

        slots = []

        for slot_number in range(1, TOTAL_SLOTS + 1):
            cursor.execute(
                """
                SELECT status
                FROM parking_slots
                WHERE slot_number=?
                """,
                (slot_number,)
            )

            row = cursor.fetchone()
            status = row["status"] if row else "Available"

            if status not in ("Available", "Occupied", "Unavailable"):
                status = "Available"

            slots.append((slot_number, status))

        conn.close()
        return slots

    def get_available_slots(self):
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT slot_number
            FROM parking_slots
            WHERE status='Available'
              AND slot_number BETWEEN 1 AND ?
            ORDER BY slot_number
            """,
            (TOTAL_SLOTS,)
        )

        slots = [row["slot_number"] for row in cursor.fetchall()]
        conn.close()

        return slots

    # --------------------------------------------------------
    # PARKING LAYOUT
    # --------------------------------------------------------

    def show_parking_layout(self):
        self.clear_content()

        content = self.create_scrollable_page(
            self.content_area
        )

        self.add_header(
            content,
            "Parking Slot Layout",
            "50 fixed parking slots • Scroll to view the complete layout"
        )

        counts = self.get_slot_counts()

        summary = tk.Frame(content, bg=APP_BG)
        summary.pack(fill="x", padx=28, pady=(0, 10))

        self.small_stat(summary, "Available", counts["Available"], SUCCESS)
        self.small_stat(summary, "Occupied", counts["Occupied"], DANGER)
        self.small_stat(summary, "Unavailable", counts["Unavailable"], UNAVAILABLE)

        card = self.make_card(content, padding=16)

        top = tk.Frame(card, bg=CARD_BG)
        top.pack(fill="x", pady=(0, 12))

        ttk.Label(
            top,
            text="All Parking Slots",
            style="CardTitle.TLabel"
        ).pack(side="left")

        self.make_button(
            top,
            "Refresh",
            self.show_parking_layout
        ).pack(side="right")

        if self.role in ("Admin", "Staff"):
            self.make_button(
                top,
                "Manage Availability",
                self.show_manage_availability
            ).pack(side="right", padx=(0, 8))

        grid = tk.Frame(card, bg=CARD_BG)
        grid.pack(fill="x")

        slots = self.get_slots()

        # 5 columns x 10 rows = exactly 50 slots.
        for index, (slot_number, status) in enumerate(slots):
            row = index // 5
            column = index % 5

            self.slot_box(
                grid,
                slot_number,
                status,
                row,
                column
            )

        legend = tk.Frame(card, bg=CARD_BG)
        legend.pack(fill="x", pady=(20, 0))

        self.legend_item(
            legend,
            "Available",
            self.colors["Available"],
            self.text_colors["Available"]
        )
        self.legend_item(
            legend,
            "Occupied",
            self.colors["Occupied"],
            self.text_colors["Occupied"]
        )
        self.legend_item(
            legend,
            "Unavailable",
            self.colors["Unavailable"],
            self.text_colors["Unavailable"]
        )

    def small_stat(self, parent, title, value, accent):
        frame = tk.Frame(
            parent,
            bg=CARD_BG,
            highlightbackground=BORDER,
            highlightthickness=1
        )
        frame.pack(
            side="left",
            fill="both",
            expand=True,
            padx=5
        )

        tk.Label(
            frame,
            text=title,
            bg=CARD_BG,
            fg=MUTED,
            font=("Segoe UI", 9, "bold")
        ).pack(pady=(12, 0))

        tk.Label(
            frame,
            text=str(value),
            bg=CARD_BG,
            fg=accent,
            font=("Segoe UI", 19, "bold")
        ).pack(pady=(2, 12))

    def slot_box(self, parent, slot_number, status, row, column):
        # Larger boxes + smaller font ensure all status text fits.
        box = tk.Frame(
            parent,
            bg=self.colors[status],
            highlightbackground="#cbd5e1",
            highlightthickness=1,
            width=125,
            height=72
        )
        box.grid(
            row=row,
            column=column,
            padx=6,
            pady=6,
            sticky="nsew"
        )
        box.grid_propagate(False)

        parent.grid_columnconfigure(
            column,
            weight=1,
            uniform="slot_columns"
        )

        tk.Label(
            box,
            text=f"Slot {slot_number}",
            bg=self.colors[status],
            fg=self.text_colors[status],
            font=("Segoe UI", 9, "bold")
        ).pack(pady=(8, 0))

        tk.Label(
            box,
            text=status,
            bg=self.colors[status],
            fg=self.text_colors[status],
            font=("Segoe UI", 8, "bold"),
            anchor="center",
            justify="center"
        ).pack(fill="x", pady=(2, 7), padx=2)

    def legend_item(self, parent, text, bg_color, fg_color):
        item = tk.Frame(parent, bg=CARD_BG)
        item.pack(side="left", padx=(0, 25))

        tk.Label(
            item,
            text="  ",
            bg=bg_color,
            relief="solid",
            bd=1
        ).pack(side="left", padx=(0, 5))

        tk.Label(
            item,
            text=text,
            bg=CARD_BG,
            fg=fg_color,
            font=("Segoe UI", 9)
        ).pack(side="left")

    # --------------------------------------------------------
    # MANAGE AVAILABILITY
    # --------------------------------------------------------

    def show_manage_availability(self):
        self.clear_content()

        content = self.create_scrollable_page(
            self.content_area
        )

        self.add_header(
            content,
            "Manage Slot Availability",
            "Staff can manage maintenance/fault status. Admin has full parking control."
        )

        card = self.make_card(content)

        ttk.Label(
            card,
            text="Change Parking Slot Status",
            style="CardTitle.TLabel"
        ).pack(anchor="w")

        ttk.Label(
            card,
            text=(
                "Available = ready for parking  •  "
                "Occupied = vehicle parked  •  "
                "Unavailable = maintenance/fault"
            ),
            style="Muted.TLabel"
        ).pack(anchor="w", pady=(3, 20))

        form = tk.Frame(card, bg=CARD_BG)
        form.pack(fill="x")

        # Slot
        tk.Label(
            form,
            text="Select Slot",
            bg=CARD_BG,
            fg=TEXT,
            font=("Segoe UI", 10, "bold")
        ).grid(row=0, column=0, sticky="w", pady=5)

        slot_var = tk.StringVar(value="Slot 1")

        slot_combo = ttk.Combobox(
            form,
            textvariable=slot_var,
            values=[f"Slot {i}" for i in range(1, TOTAL_SLOTS + 1)],
            state="readonly",
            width=25
        )
        slot_combo.grid(row=1, column=0, sticky="ew", pady=(0, 15), padx=(0, 20))

        # Status
        tk.Label(
            form,
            text="New Status",
            bg=CARD_BG,
            fg=TEXT,
            font=("Segoe UI", 10, "bold")
        ).grid(row=0, column=1, sticky="w", pady=5)

        status_var = tk.StringVar(value="Available")

        status_combo = ttk.Combobox(
            form,
            textvariable=status_var,
            values=["Available", "Occupied", "Unavailable"],
            state="readonly",
            width=25
        )
        status_combo.grid(row=1, column=1, sticky="ew", pady=(0, 15))

        # Reason
        tk.Label(
            form,
            text="Reason (for Unavailable)",
            bg=CARD_BG,
            fg=TEXT,
            font=("Segoe UI", 10, "bold")
        ).grid(row=2, column=0, sticky="w", pady=5)

        reason_var = tk.StringVar(value="Maintenance")

        reason_combo = ttk.Combobox(
            form,
            textvariable=reason_var,
            values=[
                "Maintenance",
                "Technical Fault",
                "Construction",
                "Cleaning",
                "Other"
            ],
            state="readonly",
            width=25
        )
        reason_combo.grid(row=3, column=0, sticky="ew", pady=(0, 15), padx=(0, 20))

        current_label = ttk.Label(
            form,
            text="Current Status: Available",
            style="Body.TLabel"
        )
        current_label.grid(row=3, column=1, sticky="w")

        form.grid_columnconfigure(0, weight=1)
        form.grid_columnconfigure(1, weight=1)

        def read_current(event=None):
            try:
                slot_number = int(slot_var.get().replace("Slot ", ""))
            except ValueError:
                return

            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT status
                FROM parking_slots
                WHERE slot_number=?
                """,
                (slot_number,)
            )
            row = cursor.fetchone()
            conn.close()

            current = row["status"] if row else "Available"
            current_label.config(
                text=f"Current Status: {current}"
            )
            status_var.set(current)

        slot_combo.bind("<<ComboboxSelected>>", read_current)
        read_current()

        def save_status():
            try:
                slot_number = int(
                    slot_var.get().replace("Slot ", "")
                )
            except ValueError:
                messagebox.showerror(
                    "Invalid Slot",
                    "Please select a valid slot."
                )
                return

            new_status = status_var.get()

            if new_status not in (
                "Available",
                "Occupied",
                "Unavailable"
            ):
                messagebox.showerror(
                    "Invalid Status",
                    "Please select a valid status."
                )
                return

            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT status
                FROM parking_slots
                WHERE slot_number=?
                """,
                (slot_number,)
            )
            row = cursor.fetchone()

            if row is None:
                conn.close()
                messagebox.showerror(
                    "Error",
                    "Parking slot does not exist."
                )
                return

            old_status = row["status"]

            # Staff can manage maintenance status, but should not
            # manually create an occupied slot without a vehicle.
            if self.role == "Staff" and new_status == "Occupied":
                conn.close()
                messagebox.showwarning(
                    "Use Vehicle Entry",
                    "Staff cannot manually mark a slot Occupied.\n\n"
                    "Use Vehicle Entry to park a vehicle."
                )
                return

            # Protect data consistency.
            if old_status == "Occupied" and new_status != "Occupied":
                conn.close()
                messagebox.showwarning(
                    "Vehicle Still Parked",
                    "This slot is Occupied.\n\n"
                    "Use Vehicle Exit to make it Available."
                )
                return

            # Admin can select Occupied in the menu, but we still
            # protect the database from an occupied slot without a
            # corresponding active vehicle.
            if new_status == "Occupied":
                cursor.execute(
                    """
                    SELECT id
                    FROM vehicles
                    WHERE slot_number=?
                      AND exit_time IS NULL
                    """,
                    (slot_number,)
                )
                active_vehicle = cursor.fetchone()

                if active_vehicle is None:
                    conn.close()
                    messagebox.showwarning(
                        "Vehicle Required",
                        "A slot can be marked Occupied only when "
                        "an active vehicle is parked in it.\n\n"
                        "Use Vehicle Entry first."
                    )
                    return

            cursor.execute(
                """
                UPDATE parking_slots
                SET status=?
                WHERE slot_number=?
                """,
                (new_status, slot_number)
            )

            conn.commit()
            conn.close()

            # Routine slot availability changes are intentionally NOT
            # written to the audit trail. They are normal parking operations,
            # not security/account events.

            messagebox.showinfo(
                "Success",
                f"Slot {slot_number} is now {new_status}."
            )

            self.show_parking_layout()

        self.make_button(
            card,
            "Save Status",
            save_status,
            "Primary.TButton"
        ).pack(anchor="w", pady=(8, 0))

        ttk.Label(
            card,
            text=(
                "Note: Occupied is included as a status option, "
                "but normal Occupied/Available changes should happen "
                "through Vehicle Entry and Vehicle Exit."
            ),
            style="Muted.TLabel"
        ).pack(anchor="w", pady=(12, 0))

    # --------------------------------------------------------
    # VEHICLE ENTRY
    # --------------------------------------------------------

    def show_vehicle_entry(self):
        self.clear_content()

        content = self.create_scrollable_page(
            self.content_area
        )

        self.add_header(
            content,
            "Vehicle Entry",
            "Enter vehicle details and select an available parking slot."
        )

        card = self.make_card(content)

        ttk.Label(
            card,
            text="Vehicle Information",
            style="CardTitle.TLabel"
        ).pack(anchor="w")

        ttk.Label(
            card,
            text="All fields are validated before saving.",
            style="Muted.TLabel"
        ).pack(anchor="w", pady=(3, 20))

        form = tk.Frame(card, bg=CARD_BG)
        form.pack(fill="x")

        def field(label, row):
            tk.Label(
                form,
                text=label,
                bg=CARD_BG,
                fg=TEXT,
                font=("Segoe UI", 10, "bold")
            ).grid(
                row=row,
                column=0,
                sticky="w",
                pady=6
            )

        field("Vehicle Number", 0)
        vehicle_entry = ttk.Entry(form)
        vehicle_entry.grid(
            row=1,
            column=0,
            sticky="ew",
            padx=(0, 25),
            pady=(0, 12)
        )

        field("Owner Name", 2)
        owner_entry = ttk.Entry(form)
        owner_entry.grid(
            row=3,
            column=0,
            sticky="ew",
            padx=(0, 25),
            pady=(0, 12)
        )

        field("Vehicle Type", 4)
        type_var = tk.StringVar(value="Car")
        type_combo = ttk.Combobox(
            form,
            textvariable=type_var,
            values=["Car", "Bike", "Scooter", "Other"],
            state="readonly"
        )
        type_combo.grid(
            row=5,
            column=0,
            sticky="ew",
            padx=(0, 25),
            pady=(0, 12)
        )

        field("Parking Slot", 6)

        available = self.get_available_slots()
        slot_var = tk.StringVar()

        slot_values = [f"Slot {s}" for s in available]

        if slot_values:
            slot_var.set(slot_values[0])

        slot_combo = ttk.Combobox(
            form,
            textvariable=slot_var,
            values=slot_values,
            state="readonly"
        )
        slot_combo.grid(
            row=7,
            column=0,
            sticky="ew",
            padx=(0, 25),
            pady=(0, 15)
        )

        if not slot_values:
            slot_combo.set("No available slots")
            slot_combo.configure(state="disabled")

        form.grid_columnconfigure(0, weight=1)

        def save_entry():
            vehicle_number = vehicle_entry.get().strip().upper().replace(" ", "")
            owner_name = owner_entry.get().strip()
            vehicle_type = type_var.get()

            valid, error = validate_vehicle_number(
                vehicle_number
            )
            if not valid:
                messagebox.showerror("Invalid Vehicle Number", error)
                return

            valid, error = validate_owner_name(owner_name)
            if not valid:
                messagebox.showerror("Invalid Owner Name", error)
                return

            if vehicle_type not in (
                "Car", "Bike", "Scooter", "Other"
            ):
                messagebox.showerror(
                    "Invalid Vehicle Type",
                    "Please select a valid vehicle type."
                )
                return

            selected = slot_var.get()

            if not selected.startswith("Slot "):
                messagebox.showerror(
                    "No Slot Selected",
                    "Please select an available parking slot."
                )
                return

            try:
                slot_number = int(
                    selected.replace("Slot ", "")
                )
            except ValueError:
                messagebox.showerror(
                    "Invalid Slot",
                    "Please select a valid parking slot."
                )
                return

            conn = get_connection()
            cursor = conn.cursor()

            # Prevent the same vehicle from being parked twice.
            cursor.execute(
                """
                SELECT id
                FROM vehicles
                WHERE UPPER(vehicle_number)=?
                  AND exit_time IS NULL
                """,
                (vehicle_number,)
            )

            if cursor.fetchone() is not None:
                conn.close()
                messagebox.showerror(
                    "Vehicle Already Parked",
                    "This vehicle is already parked."
                )
                return

            cursor.execute(
                """
                SELECT status
                FROM parking_slots
                WHERE slot_number=?
                """,
                (slot_number,)
            )

            slot = cursor.fetchone()

            if slot is None or slot["status"] != "Available":
                conn.close()
                messagebox.showerror(
                    "Slot Unavailable",
                    "The selected slot is no longer available. "
                    "Please refresh and choose another slot."
                )
                return

            entry_time = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            cursor.execute(
                """
                INSERT INTO vehicles
                (
                    vehicle_number,
                    owner_name,
                    vehicle_type,
                    slot_number,
                    entry_time,
                    exit_time
                )
                VALUES (?, ?, ?, ?, ?, NULL)
                """,
                (
                    vehicle_number,
                    owner_name,
                    vehicle_type,
                    slot_number,
                    entry_time
                )
            )

            cursor.execute(
                """
                UPDATE parking_slots
                SET status='Occupied'
                WHERE slot_number=?
                """,
                (slot_number,)
            )

            conn.commit()
            conn.close()

            create_audit_log(
                self.username,
                f"Vehicle entry: {vehicle_number}, Slot {slot_number}"
            )

            messagebox.showinfo(
                "Success",
                f"Vehicle parked successfully in Slot {slot_number}."
            )

            self.show_parking_layout()

        self.make_button(
            card,
            "Save Vehicle Entry",
            save_entry,
            "Primary.TButton"
        ).pack(anchor="w", pady=(8, 0))

    # --------------------------------------------------------
    # VIEW VEHICLES
    # --------------------------------------------------------

    def show_vehicles(self):
        self.clear_content()

        content = self.create_scrollable_page(
            self.content_area
        )

        self.add_header(
            content,
            "Vehicle Records",
            "View current and previous parking records."
        )

        card = self.make_card(content)

        top = tk.Frame(card, bg=CARD_BG)
        top.pack(fill="x", pady=(0, 10))

        ttk.Label(
            top,
            text="All Vehicle Records",
            style="CardTitle.TLabel"
        ).pack(side="left")

        self.make_button(
            top,
            "Refresh",
            self.show_vehicles
        ).pack(side="right")

        columns = (
            "id",
            "vehicle",
            "owner",
            "type",
            "slot",
            "entry",
            "exit"
        )

        tree = ttk.Treeview(
            card,
            columns=columns,
            show="headings",
            height=14
        )

        headings = {
            "id": "ID",
            "vehicle": "Vehicle Number",
            "owner": "Owner",
            "type": "Type",
            "slot": "Slot",
            "entry": "Entry Time",
            "exit": "Exit Time"
        }

        widths = {
            "id": 55,
            "vehicle": 130,
            "owner": 150,
            "type": 90,
            "slot": 70,
            "entry": 150,
            "exit": 150
        }

        for column in columns:
            tree.heading(
                column,
                text=headings[column]
            )
            tree.column(
                column,
                width=widths[column],
                anchor="center"
            )

        scrollbar = ttk.Scrollbar(
            card,
            orient="vertical",
            command=tree.yview
        )
        tree.configure(yscrollcommand=scrollbar.set)

        tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                id,
                vehicle_number,
                owner_name,
                vehicle_type,
                slot_number,
                entry_time,
                exit_time
            FROM vehicles
            ORDER BY id DESC
            """
        )

        rows = cursor.fetchall()
        conn.close()

        for row in rows:
            tree.insert(
                "",
                "end",
                values=(
                    row["id"],
                    row["vehicle_number"],
                    row["owner_name"],
                    row["vehicle_type"],
                    f"Slot {row['slot_number']}",
                    row["entry_time"],
                    row["exit_time"] or "Parked"
                )
            )

    # --------------------------------------------------------
    # VEHICLE EXIT
    # --------------------------------------------------------

    def show_vehicle_exit(self):
        self.clear_content()

        content = self.create_scrollable_page(
            self.content_area
        )

        self.add_header(
            content,
            "Vehicle Exit",
            "Select a currently parked vehicle and release its slot."
        )

        card = self.make_card(content)

        ttk.Label(
            card,
            text="Currently Parked Vehicles",
            style="CardTitle.TLabel"
        ).pack(anchor="w")

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                id,
                vehicle_number,
                owner_name,
                vehicle_type,
                slot_number,
                entry_time
            FROM vehicles
            WHERE exit_time IS NULL
            ORDER BY slot_number
            """
        )

        vehicles = cursor.fetchall()
        conn.close()

        if not vehicles:
            ttk.Label(
                card,
                text="No vehicles are currently parked.",
                style="Muted.TLabel"
            ).pack(anchor="w", pady=15)
            return

        values = [
            f"Slot {row['slot_number']} | "
            f"{row['vehicle_number']} | "
            f"{row['owner_name']}"
            for row in vehicles
        ]

        selected_var = tk.StringVar(value=values[0])

        combo = ttk.Combobox(
            card,
            textvariable=selected_var,
            values=values,
            state="readonly",
            width=70
        )
        combo.pack(anchor="w", pady=(15, 12))

        details = ttk.Label(
            card,
            text="",
            style="Body.TLabel"
        )
        details.pack(anchor="w", pady=(0, 15))

        def update_details(event=None):
            index = combo.current()
            if index < 0:
                return

            row = vehicles[index]

            details.config(
                text=(
                    f"Vehicle: {row['vehicle_number']}    "
                    f"Owner: {row['owner_name']}    "
                    f"Type: {row['vehicle_type']}    "
                    f"Entry: {row['entry_time']}"
                )
            )

        combo.bind(
            "<<ComboboxSelected>>",
            update_details
        )
        update_details()

        def process_exit():
            index = combo.current()

            if index < 0:
                messagebox.showerror(
                    "Error",
                    "Please select a vehicle."
                )
                return

            row = vehicles[index]
            vehicle_id = row["id"]
            slot_number = row["slot_number"]

            confirm = messagebox.askyesno(
                "Confirm Vehicle Exit",
                (
                    f"Vehicle {row['vehicle_number']} will exit "
                    f"from Slot {slot_number}.\n\n"
                    "Continue?"
                )
            )

            if not confirm:
                return

            exit_time = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                UPDATE vehicles
                SET exit_time=?
                WHERE id=?
                  AND exit_time IS NULL
                """,
                (exit_time, vehicle_id)
            )

            if cursor.rowcount == 0:
                conn.close()
                messagebox.showerror(
                    "Error",
                    "This vehicle has already exited."
                )
                return

            cursor.execute(
                """
                UPDATE parking_slots
                SET status='Available'
                WHERE slot_number=?
                """,
                (slot_number,)
            )

            conn.commit()
            conn.close()

            create_audit_log(
                self.username,
                f"Vehicle exit: {row['vehicle_number']}, Slot {slot_number}"
            )

            messagebox.showinfo(
                "Success",
                f"Vehicle exited. Slot {slot_number} is now Available."
            )

            self.show_parking_layout()

        self.make_button(
            card,
            "Process Vehicle Exit",
            process_exit,
            "Primary.TButton"
        ).pack(anchor="w")

    # --------------------------------------------------------
    # NOTIFICATIONS
    # --------------------------------------------------------

    def show_notifications(self):
        if self.role != "Admin":
            messagebox.showerror(
                "Access Denied",
                "Only Admin can view notifications."
            )
            return

        self.clear_content()

        content = self.create_scrollable_page(
            self.content_area
        )

        unread_count = get_unread_notification_count()

        self.add_header(
            content,
            "Notifications",
            f"New user registrations and other important account notifications. "
            f"Unread: {unread_count}"
        )

        card = self.make_card(content)

        top = tk.Frame(card, bg=CARD_BG)
        top.pack(fill="x", pady=(0, 12))

        ttk.Label(
            top,
            text="New User Notifications",
            style="CardTitle.TLabel"
        ).pack(side="left")

        columns = ("id", "username", "message", "created_at", "status")

        tree = ttk.Treeview(
            card,
            columns=columns,
            show="headings",
            height=12
        )

        tree.heading("id", text="ID")
        tree.heading("username", text="Username")
        tree.heading("message", text="Notification")
        tree.heading("created_at", text="Date & Time")
        tree.heading("status", text="Status")

        tree.column("id", width=60, anchor="center")
        tree.column("username", width=150, anchor="center")
        tree.column("message", width=320, anchor="w")
        tree.column("created_at", width=180, anchor="center")
        tree.column("status", width=100, anchor="center")

        tree.pack(fill="x")

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, username, message, created_at, read
            FROM notifications
            ORDER BY id DESC
            """
        )

        notifications = cursor.fetchall()
        conn.close()

        for notification in notifications:
            status = "Read" if notification["read"] else "New"

            tree.insert(
                "",
                "end",
                values=(
                    notification["id"],
                    notification["username"],
                    notification["message"],
                    notification["created_at"],
                    status
                )
            )

        if notifications:
            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute(
                "UPDATE notifications SET read=1 WHERE read=0"
            )

            conn.commit()
            conn.close()

            ttk.Label(
                card,
                text="New notifications are marked as read when Admin opens this page.",
                style="CardInfo.TLabel"
            ).pack(anchor="w", pady=(10, 0))
        else:
            ttk.Label(
                card,
                text="No notifications yet.",
                style="CardInfo.TLabel"
            ).pack(anchor="w", pady=(10, 0))

    # --------------------------------------------------------
    # USER MANAGEMENT
    # --------------------------------------------------------

    def show_user_management(self):
        if self.role != "Admin":
            messagebox.showerror(
                "Access Denied",
                "Only Admin can manage users."
            )
            return

        self.clear_content()

        content = self.create_scrollable_page(
            self.content_area
        )

        self.add_header(
            content,
            "User Management",
            "Create users, view accounts, delete users and reset passwords."
        )

        # Add user
        add_card = self.make_card(content)

        ttk.Label(
            add_card,
            text="Add New User",
            style="CardTitle.TLabel"
        ).pack(anchor="w")

        form = tk.Frame(add_card, bg=CARD_BG)
        form.pack(fill="x", pady=(15, 0))

        tk.Label(
            form,
            text="Username",
            bg=CARD_BG,
            fg=TEXT,
            font=("Segoe UI", 10, "bold")
        ).grid(row=0, column=0, sticky="w")

        username_entry = ttk.Entry(form)
        username_entry.grid(
            row=1,
            column=0,
            sticky="ew",
            padx=(0, 15),
            pady=(4, 12)
        )

        tk.Label(
            form,
            text="Password",
            bg=CARD_BG,
            fg=TEXT,
            font=("Segoe UI", 10, "bold")
        ).grid(row=0, column=1, sticky="w")

        password_entry = ttk.Entry(form, show="*")
        password_entry.grid(
            row=1,
            column=1,
            sticky="ew",
            padx=(0, 15),
            pady=(4, 12)
        )

        tk.Label(
            form,
            text="Role",
            bg=CARD_BG,
            fg=TEXT,
            font=("Segoe UI", 10, "bold")
        ).grid(row=0, column=2, sticky="w")

        role_var = tk.StringVar(value="User")

        role_combo = ttk.Combobox(
            form,
            textvariable=role_var,
            values=["Admin", "Staff", "User"],
            state="readonly"
        )
        role_combo.grid(
            row=1,
            column=2,
            sticky="ew",
            padx=(0, 15),
            pady=(4, 12)
        )

        form.grid_columnconfigure(0, weight=1)
        form.grid_columnconfigure(1, weight=1)
        form.grid_columnconfigure(2, weight=1)

        def save_user():
            username = username_entry.get().strip()
            password = password_entry.get()
            selected_role = role_var.get()

            valid, error = validate_username(username)
            if not valid:
                messagebox.showerror(
                    "Invalid Username",
                    error
                )
                return

            valid, error = validate_password(password)
            if not valid:
                messagebox.showerror(
                    "Invalid Password",
                    error
                )
                return

            if selected_role not in (
                "Admin", "Staff", "User"
            ):
                messagebox.showerror(
                    "Invalid Role",
                    "Please select a valid role."
                )
                return

            conn = get_connection()
            cursor = conn.cursor()

            try:
                cursor.execute(
                    """
                    INSERT INTO users
                    (username, password, role)
                    VALUES (?, ?, ?)
                    """,
                    (
                        username,
                        hash_password(password),
                        selected_role
                    )
                )
                conn.commit()
            except sqlite3.IntegrityError:
                conn.close()
                messagebox.showerror(
                    "Error",
                    "This username already exists."
                )
                return

            conn.close()

            create_audit_log(
                self.username,
                f"Created user '{username}' with role {selected_role}"
            )

            messagebox.showinfo(
                "Success",
                "User created successfully."
            )

            self.show_user_management()

        self.make_button(
            add_card,
            "Add User",
            save_user,
            "Primary.TButton"
        ).pack(anchor="w", pady=(5, 0))

        # Existing users
        users_card = self.make_card(content)

        top = tk.Frame(users_card, bg=CARD_BG)
        top.pack(fill="x", pady=(0, 10))

        ttk.Label(
            top,
            text="Existing Users",
            style="CardTitle.TLabel"
        ).pack(side="left")

        columns = ("id", "username", "role")

        tree = ttk.Treeview(
            users_card,
            columns=columns,
            show="headings",
            height=8
        )

        tree.heading("id", text="ID")
        tree.heading("username", text="Username")
        tree.heading("role", text="Role")

        tree.column("id", width=70, anchor="center")
        tree.column("username", width=200, anchor="center")
        tree.column("role", width=150, anchor="center")

        tree.pack(fill="x")

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, username, role
            FROM users
            ORDER BY id
            """
        )

        users = cursor.fetchall()
        conn.close()

        for user in users:
            tree.insert(
                "",
                "end",
                values=(
                    user["id"],
                    user["username"],
                    user["role"]
                )
            )

        buttons = tk.Frame(users_card, bg=CARD_BG)
        buttons.pack(fill="x", pady=(12, 0))

        def selected_user():
            selection = tree.selection()

            if not selection:
                messagebox.showwarning(
                    "Select User",
                    "Please select a user first."
                )
                return None

            values = tree.item(
                selection[0],
                "values"
            )

            return values

        def delete_selected():
            values = selected_user()
            if values is None:
                return

            target_username = values[1]

            if target_username == "admin":
                messagebox.showwarning(
                    "Protected Account",
                    "The default admin account cannot be deleted."
                )
                return

            if target_username == self.username:
                messagebox.showwarning(
                    "Not Allowed",
                    "You cannot delete your own account."
                )
                return

            if not messagebox.askyesno(
                "Confirm Delete",
                f"Delete user '{target_username}'?"
            ):
                return

            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute(
                "DELETE FROM users WHERE username=?",
                (target_username,)
            )

            conn.commit()
            conn.close()

            create_audit_log(
                self.username,
                f"Deleted user '{target_username}'"
            )

            messagebox.showinfo(
                "Success",
                "User deleted successfully."
            )

            self.show_user_management()

        def reset_selected():
            values = selected_user()
            if values is None:
                return

            self.show_reset_password(values[1])

        self.make_button(
            buttons,
            "Reset Password",
            reset_selected
        ).pack(side="left", padx=(0, 8))

        self.make_button(
            buttons,
            "Delete User",
            delete_selected,
            "Danger.TButton"
        ).pack(side="left")

    # --------------------------------------------------------
    # RESET PASSWORD
    # --------------------------------------------------------

    def show_reset_password(self, selected_username=None):
        if self.role != "Admin":
            messagebox.showerror(
                "Access Denied",
                "Only Admin can reset passwords."
            )
            return

        self.clear_content()

        content = self.create_scrollable_page(
            self.content_area
        )

        self.add_header(
            content,
            "Reset Password",
            "Passwords are stored using secure salted PBKDF2 hashing."
        )

        card = self.make_card(content)

        form = tk.Frame(card, bg=CARD_BG)
        form.pack(fill="x")

        tk.Label(
            form,
            text="Username",
            bg=CARD_BG,
            fg=TEXT,
            font=("Segoe UI", 10, "bold")
        ).pack(anchor="w")

        username_var = tk.StringVar(
            value=selected_username or ""
        )

        username_entry = ttk.Entry(
            form,
            textvariable=username_var
        )
        username_entry.pack(
            fill="x",
            pady=(5, 15)
        )

        tk.Label(
            form,
            text="New Password",
            bg=CARD_BG,
            fg=TEXT,
            font=("Segoe UI", 10, "bold")
        ).pack(anchor="w")

        new_password = ttk.Entry(
            form,
            show="*"
        )
        new_password.pack(
            fill="x",
            pady=(5, 15)
        )

        tk.Label(
            form,
            text="Confirm Password",
            bg=CARD_BG,
            fg=TEXT,
            font=("Segoe UI", 10, "bold")
        ).pack(anchor="w")

        confirm_password = ttk.Entry(
            form,
            show="*"
        )
        confirm_password.pack(
            fill="x",
            pady=(5, 15)
        )

        def reset():
            username = username_var.get().strip()
            password = new_password.get()
            confirm = confirm_password.get()

            if not username:
                messagebox.showerror(
                    "Error",
                    "Please enter a username."
                )
                return

            valid, error = validate_password(password)

            if not valid:
                messagebox.showerror(
                    "Invalid Password",
                    error
                )
                return

            if password != confirm:
                messagebox.showerror(
                    "Password Mismatch",
                    "Passwords do not match."
                )
                return

            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute(
                "SELECT id FROM users WHERE username=?",
                (username,)
            )

            if cursor.fetchone() is None:
                conn.close()
                messagebox.showerror(
                    "User Not Found",
                    "That username does not exist."
                )
                return

            cursor.execute(
                """
                UPDATE users
                SET password=?
                WHERE username=?
                """,
                (hash_password(password), username)
            )

            conn.commit()
            conn.close()

            create_audit_log(
                self.username,
                f"Reset password for '{username}'"
            )

            messagebox.showinfo(
                "Success",
                "Password reset successfully."
            )

            self.show_user_management()

        self.make_button(
            card,
            "Reset Password",
            reset,
            "Primary.TButton"
        ).pack(anchor="w")

    # --------------------------------------------------------
    # AUDIT LOGS
    # --------------------------------------------------------

    def show_audit_logs(self):
        if self.role != "Admin":
            messagebox.showerror(
                "Access Denied",
                "Only Admin can view and manage audit logs."
            )
            return

        self.clear_content()

        content = self.create_scrollable_page(
            self.content_area
        )

        self.add_header(
            content,
            "Audit Trail",
            "View, filter and securely manage recorded system activity."
        )

        # ----------------------------------------------------
        # FILTER CARD
        # ----------------------------------------------------
        filter_card = self.make_card(content)

        ttk.Label(
            filter_card,
            text="Activity Filter",
            style="CardTitle.TLabel"
        ).pack(anchor="w")

        ttk.Label(
            filter_card,
            text="Choose a time period to view the corresponding audit records.",
            style="Muted.TLabel"
        ).pack(anchor="w", pady=(3, 14))

        filter_buttons = tk.Frame(filter_card, bg=CARD_BG)
        filter_buttons.pack(fill="x", pady=(0, 12))

        selected_filter = {"name": "All"}

        def filter_range(name):
            now = datetime.now()
            today = now.replace(hour=0, minute=0, second=0, microsecond=0)

            if name == "Today":
                return today, today + timedelta(days=1)
            if name == "Yesterday":
                return today - timedelta(days=1), today
            if name == "This Week":
                start = today - timedelta(days=today.weekday())
                return start, start + timedelta(days=7)
            if name == "This Month":
                if today.month == 12:
                    end = today.replace(
                        year=today.year + 1,
                        month=1,
                        day=1
                    )
                else:
                    end = today.replace(
                        month=today.month + 1,
                        day=1
                    )
                return today.replace(day=1), end
            if name == "This Year":
                return (
                    today.replace(month=1, day=1),
                    today.replace(
                        year=today.year + 1,
                        month=1,
                        day=1
                    )
                )
            return None, None

        def load_logs():
            name = selected_filter["name"]
            start_date, end_date = filter_range(name)

            for item in tree.get_children():
                tree.delete(item)

            conn = get_connection()
            cursor = conn.cursor()

            if start_date is None:
                cursor.execute(
                    """
                    SELECT id, user_id, username, role, action, timestamp
                    FROM audit_logs
                    ORDER BY id DESC
                    """
                )
            else:
                cursor.execute(
                    """
                    SELECT id, user_id, username, role, action, timestamp
                    FROM audit_logs
                    WHERE timestamp >= ?
                      AND timestamp < ?
                    ORDER BY id DESC
                    """,
                    (
                        start_date.strftime("%Y-%m-%d %H:%M:%S"),
                        end_date.strftime("%Y-%m-%d %H:%M:%S")
                    )
                )

            logs = cursor.fetchall()
            conn.close()

            for log in logs:
                tree.insert(
                    "",
                    "end",
                    values=(
                        log["user_id"] if log["user_id"] is not None else "-",
                        log["username"],
                        log["role"] if log["role"] else "-",
                        log["action"],
                        log["timestamp"]
                    )
                )

            period_label.config(
                text=f"Showing: {name}  •  {len(logs)} record(s)"
            )

        def set_filter(name):
            selected_filter["name"] = name
            load_logs()

        for name in (
            "Today",
            "Yesterday",
            "This Week",
            "This Month",
            "This Year",
            "All"
        ):
            self.make_button(
                filter_buttons,
                name,
                lambda n=name: set_filter(n),
                "Secondary.TButton"
            ).pack(side="left", padx=(0, 7))

        period_label = ttk.Label(
            filter_card,
            text="Showing: All",
            style="Muted.TLabel"
        )
        period_label.pack(anchor="w")

        # ----------------------------------------------------
        # CUSTOM DATE RANGE
        # ----------------------------------------------------
        custom_frame = tk.Frame(filter_card, bg=CARD_BG)
        custom_frame.pack(fill="x", pady=(16, 0))

        tk.Label(
            custom_frame,
            text="Custom View: From",
            bg=CARD_BG,
            fg=TEXT,
            font=("Segoe UI", 9, "bold")
        ).pack(side="left")

        from_entry = ttk.Entry(custom_frame, width=14)
        from_entry.pack(side="left", padx=(7, 8))
        from_entry.insert(0, datetime.now().strftime("%Y-%m-%d"))

        tk.Label(
            custom_frame,
            text="To",
            bg=CARD_BG,
            fg=TEXT,
            font=("Segoe UI", 9, "bold")
        ).pack(side="left")

        to_entry = ttk.Entry(custom_frame, width=14)
        to_entry.pack(side="left", padx=(7, 8))
        to_entry.insert(0, datetime.now().strftime("%Y-%m-%d"))

        def custom_view():
            try:
                start = datetime.strptime(
                    from_entry.get().strip(),
                    "%Y-%m-%d"
                )
                end_day = datetime.strptime(
                    to_entry.get().strip(),
                    "%Y-%m-%d"
                )
            except ValueError:
                messagebox.showerror(
                    "Invalid Date",
                    "Use the date format YYYY-MM-DD."
                )
                return

            if end_day < start:
                messagebox.showerror(
                    "Invalid Range",
                    "The To date cannot be earlier than the From date."
                )
                return

            end = end_day + timedelta(days=1)

            for item in tree.get_children():
                tree.delete(item)

            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, user_id, username, role, action, timestamp
                FROM audit_logs
                WHERE timestamp >= ?
                  AND timestamp < ?
                ORDER BY id DESC
                """,
                (
                    start.strftime("%Y-%m-%d 00:00:00"),
                    end.strftime("%Y-%m-%d 00:00:00")
                )
            )
            logs = cursor.fetchall()
            conn.close()

            for log in logs:
                tree.insert(
                    "",
                    "end",
                    values=(
                        log["user_id"] if log["user_id"] is not None else "-",
                        log["username"],
                        log["role"] if log["role"] else "-",
                        log["action"],
                        log["timestamp"]
                    )
                )

            period_label.config(
                text=(
                    f"Showing: {start.strftime('%Y-%m-%d')} to "
                    f"{end_day.strftime('%Y-%m-%d')}  •  "
                    f"{len(logs)} record(s)"
                )
            )

        self.make_button(
            custom_frame,
            "Apply Custom View",
            custom_view,
            "Primary.TButton"
        ).pack(side="left")

        # ----------------------------------------------------
        # LOG TABLE
        # ----------------------------------------------------
        card = self.make_card(content)

        top = tk.Frame(card, bg=CARD_BG)
        top.pack(fill="x", pady=(0, 10))

        ttk.Label(
            top,
            text="System Activity",
            style="CardTitle.TLabel"
        ).pack(side="left")

        self.make_button(
            top,
            "Refresh",
            load_logs
        ).pack(side="right")

        columns = (
            "user_id",
            "username",
            "role",
            "action",
            "timestamp"
        )

        table_frame = tk.Frame(card, bg=CARD_BG)
        table_frame.pack(fill="both", expand=True)

        tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            height=18
        )

        tree.heading("user_id", text="User ID")
        tree.heading("username", text="Username")
        tree.heading("role", text="Role")
        tree.heading("action", text="Action")
        tree.heading("timestamp", text="Timestamp")

        tree.column("user_id", width=80, anchor="center")
        tree.column("username", width=130, anchor="center")
        tree.column("role", width=100, anchor="center")
        tree.column("action", width=520, anchor="w")
        tree.column("timestamp", width=175, anchor="center")

        scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=tree.yview
        )
        tree.configure(yscrollcommand=scrollbar.set)

        tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # ----------------------------------------------------
        # DELETE AUDIT LOGS - ADMIN ONLY
        # ----------------------------------------------------
        delete_card = self.make_card(content)

        ttk.Label(
            delete_card,
            text="Audit Trail Maintenance",
            style="CardTitle.TLabel"
        ).pack(anchor="w")

        ttk.Label(
            delete_card,
            text=(
                "Only Admin can permanently delete audit records. "
                "Choose a period or enter a custom date range."
            ),
            style="Muted.TLabel"
        ).pack(anchor="w", pady=(3, 14))

        delete_controls = tk.Frame(delete_card, bg=CARD_BG)
        delete_controls.pack(fill="x")

        tk.Label(
            delete_controls,
            text="Delete:",
            bg=CARD_BG,
            fg=TEXT,
            font=("Segoe UI", 10, "bold")
        ).pack(side="left")

        delete_var = tk.StringVar(value="Last 7 Days")
        delete_combo = ttk.Combobox(
            delete_controls,
            textvariable=delete_var,
            values=[
                "Last 7 Days",
                "Last 30 Days",
                "Last 90 Days",
                "Custom Range",
                "All Audit Logs"
            ],
            state="readonly",
            width=20
        )
        delete_combo.pack(side="left", padx=(8, 10))

        def get_delete_range():
            now = datetime.now()
            choice = delete_var.get()

            if choice == "Last 7 Days":
                return now - timedelta(days=7), now, "the last 7 days"

            if choice == "Last 30 Days":
                return now - timedelta(days=30), now, "the last 30 days"

            if choice == "Last 90 Days":
                return now - timedelta(days=90), now, "the last 90 days"

            if choice == "All Audit Logs":
                return None, None, "all audit logs"

            try:
                start = datetime.strptime(
                    from_entry.get().strip(),
                    "%Y-%m-%d"
                )
                end_day = datetime.strptime(
                    to_entry.get().strip(),
                    "%Y-%m-%d"
                )
            except ValueError:
                messagebox.showerror(
                    "Invalid Date",
                    "Use the date format YYYY-MM-DD for the custom range."
                )
                return "ERROR", "ERROR", ""

            if end_day < start:
                messagebox.showerror(
                    "Invalid Range",
                    "The To date cannot be earlier than the From date."
                )
                return "ERROR", "ERROR", ""

            end = end_day + timedelta(days=1)
            description = (
                f"records from {start.strftime('%Y-%m-%d')} "
                f"to {end_day.strftime('%Y-%m-%d')}"
            )
            return start, end, description

        def delete_audit_logs():
            start_date, end_date, description = get_delete_range()

            if start_date == "ERROR":
                return

            warning = (
                "This action permanently deletes the selected audit records.\n\n"
                f"You are about to delete {description}.\n\n"
                "This cannot be undone. Continue?"
            )

            if not messagebox.askyesno(
                "Confirm Audit Trail Deletion",
                warning,
                icon="warning"
            ):
                return

            conn = get_connection()
            cursor = conn.cursor()

            if start_date is None:
                cursor.execute("SELECT COUNT(*) AS total FROM audit_logs")
                deleted_count = cursor.fetchone()["total"]
                cursor.execute("DELETE FROM audit_logs")
            else:
                cursor.execute(
                    """
                    SELECT COUNT(*) AS total
                    FROM audit_logs
                    WHERE timestamp >= ?
                      AND timestamp < ?
                    """,
                    (
                        start_date.strftime("%Y-%m-%d %H:%M:%S"),
                        end_date.strftime("%Y-%m-%d %H:%M:%S")
                    )
                )
                deleted_count = cursor.fetchone()["total"]

                cursor.execute(
                    """
                    DELETE FROM audit_logs
                    WHERE timestamp >= ?
                      AND timestamp < ?
                    """,
                    (
                        start_date.strftime("%Y-%m-%d %H:%M:%S"),
                        end_date.strftime("%Y-%m-%d %H:%M:%S")
                    )
                )

            conn.commit()
            conn.close()

            # SQLite may keep unused pages after DELETE. VACUUM reclaims
            # that space so the database file can actually become smaller.
            conn = get_connection()
            conn.execute("VACUUM")
            conn.close()

            # Record the administrative deletion event after the cleanup.
            create_audit_log(
                self.username,
                f"Deleted {deleted_count} audit log(s): {description}"
            )

            messagebox.showinfo(
                "Audit Trail Updated",
                f"{deleted_count} audit record(s) were deleted successfully."
            )

            load_logs()

        self.make_button(
            delete_controls,
            "Delete Audit Trail",
            delete_audit_logs,
            "Danger.TButton"
        ).pack(side="left")

        ttk.Label(
            delete_card,
            text=(
                "Tip: deleting old records and running database cleanup "
                "can reduce unnecessary SQLite storage usage."
            ),
            style="Muted.TLabel"
        ).pack(anchor="w", pady=(12, 0))

        load_logs()


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":
    setup_database()
    initialize_parking_slots()

    root = tk.Tk()
    app = ParkingApp(root)
    root.mainloop()
