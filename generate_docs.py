#!/usr/bin/env python3
"""Generate a beginner-friendly PDF explaining the Zero Trust IAM Gateway project."""

from fpdf import FPDF
from pathlib import Path

OUTPUT = Path(__file__).parent / "Zero_Trust_IAM_Gateway_Guide.pdf"

GREEN = (34, 197, 94)
BLUE = (99, 102, 241)
RED = (239, 68, 68)
DARK = (30, 30, 60)
GRAY = (100, 100, 130)
LIGHT_BG = (245, 245, 250)
WHITE = (255, 255, 255)


class Doc(FPDF):
    def header(self):
        if self.page_no() > 1:
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(120, 120, 120)
            self.cell(95, 8, "Zero Trust IAM Gateway - Project Guide", align="L")
            self.cell(95, 8, f"Page {self.page_no()}", align="R")
            self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(180, 180, 180)
        self.cell(0, 10, "Built with Python, FastAPI, Docker, OpenLDAP and WireGuard", align="C")

    def title_page(self):
        self.add_page()
        self.ln(40)
        self.set_fill_color(99, 102, 241)
        self.rect(20, self.get_y(), 170, 2, "F")
        self.ln(10)
        self.set_font("Helvetica", "B", 28)
        self.set_text_color(30, 30, 60)
        self.cell(0, 14, "Zero Trust IAM Gateway", align="C")
        self.ln(16)
        self.set_font("Helvetica", "", 16)
        self.set_text_color(100, 100, 140)
        self.cell(0, 10, "A Complete Security Login System", align="C")
        self.ln(8)
        self.set_font("Helvetica", "", 12)
        self.set_text_color(140, 140, 140)
        self.cell(0, 8, "Beginner-Friendly Project Guide", align="C")
        self.ln(20)
        self.set_fill_color(99, 102, 241)
        self.rect(20, self.get_y(), 170, 2, "F")
        self.ln(25)
        self.set_font("Helvetica", "", 10)
        self.set_text_color(150, 150, 150)
        self.cell(0, 7, "This guide explains everything in simple terms.", align="C")
        self.ln(6)
        self.cell(0, 7, "No technical background required.", align="C")

    def section_title(self, num, title):
        self.set_font("Helvetica", "B", 16)
        self.set_text_color(30, 30, 60)
        label = f"{num}. {title}" if num else title
        self.cell(0, 12, label)
        self.ln(10)
        self.set_draw_color(99, 102, 241)
        self.set_line_width(1.2)
        y = self.get_y()
        self.line(self.get_x(), y, self.get_x() + 190, y)
        self.ln(12)

    def sub_title(self, title):
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(60, 60, 120)
        self.cell(0, 9, title)
        self.ln(7)

    def body(self, text):
        self.set_font("Helvetica", "", 10)
        self.set_text_color(50, 50, 50)
        self.multi_cell(0, 5.5, text)
        self.ln(2)

    def bullet(self, text):
        self.set_font("Helvetica", "", 10)
        self.set_text_color(50, 50, 50)
        self.cell(5, 5.5, "-")
        self.multi_cell(0, 5.5, text)
        self.ln(1)

    def code_block(self, text):
        self.set_fill_color(240, 240, 245)
        self.set_draw_color(200, 200, 210)
        self.set_font("Courier", "", 8)
        self.set_text_color(40, 40, 40)
        self.multi_cell(0, 4.5, text, border=1, fill=True)
        self.ln(3)

    def draw_box(self, x, y, w, h, label, fill_color=BLUE, text_color=WHITE, size=9):
        self.set_fill_color(*fill_color)
        self.set_draw_color(*fill_color)
        self.rect(x, y, w, h, "F")
        self.set_font("Helvetica", "B", size)
        self.set_text_color(*text_color)
        self.set_xy(x, y + (h - 5) / 2)
        self.cell(w, 5, label, align="C")

    def draw_arrow_right(self, x, y, length=12):
        self.set_draw_color(120, 120, 120)
        self.set_line_width(0.8)
        y_mid = y
        self.line(x, y_mid, x + length, y_mid)
        self.line(x + length - 3, y_mid - 2, x + length, y_mid)
        self.line(x + length - 3, y_mid + 2, x + length, y_mid)

    def draw_arrow_down(self, x, y, length=10):
        self.set_draw_color(120, 120, 120)
        self.set_line_width(0.8)
        x_mid = x
        self.line(x_mid, y, x_mid, y + length)
        self.line(x_mid - 2, y + length - 3, x_mid, y + length)
        self.line(x_mid + 2, y + length - 3, x_mid, y + length)


doc = Doc()
doc.set_auto_page_break(auto=True, margin=20)

# =====================================================================
# TITLE PAGE
# =====================================================================
doc.title_page()

# =====================================================================
# TABLE OF CONTENTS
# =====================================================================
doc.add_page()
doc.section_title("", "Table of Contents")
toc = [
    "What Is This Project?",
    "The Problem It Solves",
    "How Login Works (3 Layers of Security)",
    "Login Flow Diagram",
    "What Is Docker?",
    "System Architecture Diagram",
    "How to Run the Project",
    "Key Features Explained Simply",
    "User Accounts and Roles",
    "Admin Dashboard Walkthrough",
    "Troubleshooting",
]
for i, t in enumerate(toc, 1):
    doc.bullet(f"{i}. {t}")

# =====================================================================
# 1. WHAT IS THIS PROJECT?
# =====================================================================
doc.add_page()
doc.section_title("1", "What Is This Project?")
doc.body(
    "This project is a complete security login system called a 'Zero Trust IAM Gateway'. "
    "Think of it as a smart security guard for a company's online resources."
)
doc.body(
    "Imagine a company building where you need to:"
)
doc.bullet("Scan your ID card at the entrance (Layer 1 - Password)")
doc.bullet("Enter a code from your phone app (Layer 2 - TOTP)")
doc.bullet("Enter a code sent to your email (Layer 3 - Email OTP - Admin only)")
doc.body(
    "That's exactly what this system does, but for websites and online tools."
)
doc.body("The system manages five key things:")
doc.bullet("Who can log in (authentication)")
doc.bullet("What each person can access (authorization)")
doc.bullet("Keeping track of who is logged in (session management)")
doc.bullet("Making sure devices are safe (device posture)")
doc.bullet("Logging everything for security review (SIEM)")

# =====================================================================
# 2. THE PROBLEM IT SOLVES
# =====================================================================
doc.add_page()
doc.section_title("2", "The Problem It Solves")
doc.body(
    "In old-school companies, employees just used a username and password to access everything. "
    "This is dangerous because:"
)
doc.bullet("Passwords get stolen all the time")
doc.bullet("Once someone has your password, they can access everything you can")
doc.bullet("You can't prove it was really you logging in")
doc.bullet("No record of who accessed what")
doc.body(
    "This project follows the 'Zero Trust' philosophy. The name means:"
)
doc.bullet("Never trust anyone automatically -- always verify")
doc.bullet("Always ask for multiple proofs of identity")
doc.bullet("Only let people access what they specifically need for their job")
doc.bullet("Keep a permanent log of everything that happens")
doc.bullet("Check that devices are safe before allowing access")
doc.body(
    "For example, even the admin (the boss of the system) has to go through "
    "THREE layers of security: password, phone authenticator app, and email code. "
    "If any one layer fails, access is denied completely."
)

# =====================================================================
# 3. HOW LOGIN WORKS
# =====================================================================
doc.add_page()
doc.section_title("3", "How Login Works (3 Layers of Security)")

doc.sub_title("Layer 1: Username and Password")
doc.body(
    "You type your username and password on the login page. "
    "The system checks if this matches what's stored in its secure database "
    "or in the company's LDAP server (a master phone book of all employees). "
    "If it matches, you move to Layer 2."
)

doc.sub_title("Layer 2: Phone App Code (TOTP)")
doc.body(
    "A special code is generated by an app on your phone like Google Authenticator or Authy. "
    "This code changes every 30 seconds. You must type the 6-digit code shown in your phone app. "
    "Only someone with your phone AND your password can pass this layer."
)
doc.body(
    "If you lose your phone, you can use a Backup Code instead - "
    "a one-time 8-digit code that the admin gave you when setting up your account. "
    "You get 3 backup codes. Each code works exactly once, then it's used up."
)

doc.sub_title("Layer 3: Email Code (Admin Only)")
doc.body(
    "For the admin account only, after passing the phone code, "
    "a 6-digit code is sent to the admin's email address. "
    "You must check your email and type that code within 5 minutes. "
    "This proves you also have access to the admin's email account."
)

doc.sub_title("What Happens After All 3 Layers?")
doc.body(
    "Once all checks pass, the system creates a session - "
    "think of it as a temporary VIP pass that lasts 24 hours. "
    "As long as you have this pass, you can access the resources you're allowed to see. "
    "When you click Logout, the pass is destroyed immediately."
)

# =====================================================================
# 4. LOGIN FLOW DIAGRAM
# =====================================================================
doc.add_page()
doc.section_title("4", "Login Flow Diagram")
doc.body("Here is a visual walkthrough of what happens when a user logs in:")

start_y = doc.get_y() + 5
cx = 105  # center x

# Step 1: Login page
doc.draw_box(55, start_y, 100, 12, '1. User visits Login Page', BLUE)
y = start_y + 12

# Arrow down
doc.draw_arrow_down(cx, y, 10)
y += 10

# Step 2: Enter credentials
doc.draw_box(55, y, 100, 12, '2. Enter Username + Password', DARK)
y += 12

# Arrow down
doc.draw_arrow_down(cx, y, 10)
y += 10

# Step 3: Check
doc.draw_box(35, y, 140, 12, '3. Server checks password against DB / LDAP', BLUE)
y += 12

# Branch
doc.draw_arrow_down(cx, y, 8)
y += 8

# Diamond-like split
doc.set_font("Helvetica", "B", 9)
doc.set_text_color(*DARK)
doc.cell(0, 6, "Invalid? -> Show error    Valid? -> Continue", align="C")
y += 10

doc.draw_arrow_down(cx, y, 10)
y += 10

# Step 4: TOTP
doc.draw_box(55, y, 100, 12, '4. Enter 6-digit TOTP code', DARK)
y += 12

doc.draw_arrow_down(cx, y, 10)
y += 10

# Step 4b: Backup code branch
doc.set_font("Helvetica", "I", 8)
doc.set_text_color(*GRAY)
doc.cell(0, 5, "(Or use Backup Code if phone is lost)", align="C")
y += 8

doc.draw_arrow_down(cx, y, 10)
y += 10

# Step 5: Admin check
doc.draw_box(35, y, 140, 12, '5. Is this the admin account?', BLUE)
y += 12

doc.set_font("Helvetica", "B", 9)
doc.set_text_color(*DARK)
doc.cell(0, 6, "Standard User -> Session created     Admin -> Continue", align="C")
y += 10

doc.draw_arrow_down(cx, y, 10)
y += 10

# Step 6: Email OTP
doc.draw_box(40, y, 130, 12, '6. Email OTP sent to admin email', RED, WHITE, 9)
y += 12

doc.draw_arrow_down(cx, y, 10)
y += 10

# Step 7: Done
doc.draw_box(55, y, 100, 12, '7. Session created! Redirect to dashboard', GREEN)
y += 12

doc.ln(6)
doc.body(
    "Note: Standard users who don't have MFA set up skip directly to "
    "session creation after the password check. The admin can add MFA "
    "for any user from the admin dashboard."
)

# =====================================================================
# 5. WHAT IS DOCKER?
# =====================================================================
doc.add_page()
doc.section_title("5", "What Is Docker? (Simple Explanation)")
doc.body(
    "Docker is like a shipping container for software. "
    "Normally, to run a program, you need to install the right version of Python, "
    "the right database, the right operating system -- it's complicated and breaks often."
)
doc.body(
    "Docker packages the entire program with everything it needs inside a container. "
    "You can run this container on ANY computer, and it will work exactly the same way. "
    "Think of it like a food truck -- the kitchen inside is always the same, "
    "no matter where the truck parks."
)
doc.body("This project runs FOUR containers that work together:")
doc.bullet("Gateway container -- The main login system (Python + FastAPI)")
doc.bullet("WireGuard container -- Creates secure network tunnels")
doc.bullet("OpenLDAP container -- Stores user accounts like a phone book")
doc.bullet("Accounting API container -- A demo resource for testing access")
doc.body(
    "Docker Compose is a tool that starts all four containers with a single command:"
)
doc.code_block("make up")
doc.body("And stops them all with:")
doc.code_block("make down")

# =====================================================================
# 6. SYSTEM ARCHITECTURE DIAGRAM
# =====================================================================
doc.add_page()
doc.section_title("6", "System Architecture Diagram")
doc.body("This diagram shows how all the pieces connect:")

y = doc.get_y() + 5

# Brower box
doc.draw_box(55, y, 100, 14, "User's Web Browser", DARK, WHITE, 10)
y += 18

# Arrow down to gateway
doc.draw_arrow_down(105, y, 10)
y += 10

# Gateway box
doc.draw_box(55, y, 100, 16, "GATEWAY (Main System)", BLUE, WHITE, 10)
gw_bottom = y + 16
doc.set_font("Helvetica", "", 7)
doc.set_text_color(200, 200, 220)
doc.set_xy(55, gw_bottom - 7)
doc.cell(100, 5, "Python + FastAPI on port 8443", align="C")
y = gw_bottom + 8

# Three arrows from gateway
# Left arrow to OpenLDAP
doc.draw_arrow_left = lambda self, x, y, length=12: (
    self.set_draw_color(120, 120, 120),
    self.set_line_width(0.8),
    self.line(x, y, x - length, y),
    self.line(x - length + 3, y - 2, x - length, y),
    self.line(x - length + 3, y + 2, x - length, y),
)
doc.set_draw_color(120, 120, 120)
doc.set_line_width(0.8)
# Left arrow
lx, ly = 55, gw_bottom - 8
doc.line(lx, ly, lx - 35, ly)
doc.line(lx - 32, ly - 2, lx - 35, ly)
doc.line(lx - 32, ly + 2, lx - 35, ly)
# Right arrow
rx, ry = 155, gw_bottom - 8
doc.line(rx, ry, rx + 35, ry)
doc.line(rx + 32, ry - 2, rx + 35, ry)
doc.line(rx + 32, ry + 2, rx + 35, ry)

# LDAP box (left)
doc.draw_box(5, y - 20, 45, 14, "OpenLDAP", GRAY, WHITE, 8)
doc.set_font("Helvetica", "", 6)
doc.set_text_color(180, 180, 180)
doc.set_xy(5, y - 7)
doc.cell(45, 5, "Stores users", align="C")

# WireGuard box (right)
doc.draw_box(160, y - 20, 50, 14, "WireGuard VPN", GRAY, WHITE, 8)
doc.set_font("Helvetica", "", 6)
doc.set_text_color(180, 180, 180)
doc.set_xy(160, y - 7)
doc.cell(50, 5, "Network tunnel", align="C")

y += 15

# Arrow down from gateway
doc.draw_arrow_down(105, y, 10)
y += 10

# SQLite + accounting box
doc.draw_box(55, y, 100, 14, "SQLite Database + APIs", GREEN, WHITE, 9)
doc.set_font("Helvetica", "", 7)
doc.set_text_color(200, 255, 220)
doc.set_xy(55, y + 7)
doc.cell(100, 5, "store.db  |  Accounting API  |  etc.", align="C")
y += 18

doc.ln(5)
doc.body("How the pieces talk to each other:")
doc.bullet("The browser talks to the Gateway on http://localhost:8443")
doc.bullet("The Gateway checks passwords against OpenLDAP or its own database")
doc.bullet("The Gateway stores sessions, MFA keys, and logs in SQLite (store.db)")
doc.bullet("The Gateway routes users to backend resources through WireGuard")
doc.bullet("All user data persists on your computer in store.db")

# =====================================================================
# 7. HOW TO RUN THE PROJECT
# =====================================================================
doc.add_page()
doc.section_title("7", "How to Run the Project")
doc.sub_title("One-Time Requirements")
doc.body("You need Docker Desktop installed on your computer.")
doc.body("All commands run from the project folder in Terminal.")

doc.sub_title("Start Everything")
doc.code_block("make up")
doc.body("This starts all containers. Wait 10-15 seconds for everything to boot.")

doc.sub_title("Open the Login Page")
doc.code_block("open http://localhost:8443")

doc.sub_title("Login as Admin")
doc.code_block("Username: admin   Password: CHANGE_ME")  # ⚠️ CHANGE_ME — replace before deploying

doc.sub_title("Stop Everything")
doc.code_block("make down")

doc.sub_title("See Live Logs")
doc.code_block("make logs")

doc.sub_title("Check Database Status")
doc.code_block("make db")

doc.sub_title("Emergency CLI Tool")
doc.code_block(
    "docker exec wireguardproject-gateway-1 python /app/manage_users.py --help"
)
doc.code_block(
    "# Reset MFA for a user:\n"
    "docker exec wireguardproject-gateway-1 python /app/manage_users.py "
    "--reset-mfa admin"
)

doc.sub_title("Protect Database from Accidental Deletion")
doc.code_block("make lock")
doc.body("This prevents accidentally deleting store.db. Run 'make unlock' to allow deletion.")

# =====================================================================
# 8. KEY FEATURES
# =====================================================================
doc.add_page()
doc.section_title("8", "Key Features Explained Simply")

doc.sub_title("Active Directory / LDAP Sync")
doc.body(
    "The system can connect to a company's user directory -- a master phone book "
    "of all employees. When you create or delete users, it automatically syncs. "
    "Users imported from LDAP get their roles and permissions automatically assigned."
)

doc.sub_title("MFA (Multi-Factor Authentication)")
doc.body(
    "Multiple proofs of identity. Instead of just a password, "
    "you also need a code from your phone. This makes it much harder for hackers "
    "because they would need both your password AND your physical phone."
)

doc.sub_title("Backup Recovery Codes")
doc.body(
    "If you lose your phone, you cannot use the authenticator app. "
    "Backup codes are special one-time codes you can use instead. "
    "Each code works exactly once. When you run out, the admin can generate new ones. "
    "You get 3 codes when MFA is first set up."
)

doc.sub_title("Device Posture Check")
doc.body(
    "The system checks if your device is safe -- firewall active, compliant status. "
    "If your firewall is disabled, the system logs a warning but still allows access. "
    "This is like a security guard noticing your door is unlocked but still letting you in."
)

doc.sub_title("Session Management")
doc.body(
    "Once logged in, you get a session that lasts 24 hours. "
    "The admin dashboard shows all active sessions -- exactly who is logged in "
    "and for how long. The list auto-refreshes every 10 seconds. "
    "Logging out immediately destroys the session."
)

doc.sub_title("SIEM Event Log")
doc.body(
    "The system logs everything: logins, failed attempts, access grants, "
    "security risks. This is like a security camera recording. "
    "The admin can view, filter, and clear these logs from the dashboard."
)

doc.sub_title("Emergency CLI Tool")
doc.body(
    "If something goes wrong (e.g., admin loses phone AND email access), "
    "there is a command-line tool that can:"
)
doc.bullet("Reset MFA for any user")
doc.bullet("Change passwords directly in the database")
doc.bullet("Show remaining backup codes")
doc.bullet("Regenerate backup codes")

doc.sub_title("Database Protection")
doc.body(
    "The database file (store.db) contains all MFA keys, backup codes, "
    "and user data. A lock file prevents accidental deletion. "
    "You must explicitly unlock before deleting."
)

# =====================================================================
# 9. USER ACCOUNTS
# =====================================================================
doc.add_page()
doc.section_title("9", "User Accounts and Roles")

doc.sub_title("Default Admin Account")
doc.code_block("Username: admin")
doc.code_block("Password: CHANGE_ME")  # ⚠️ CHANGE_ME — replace before deploying
doc.body(
    "The admin has full access: create/delete users, view MFA keys, "
    "reset passwords, clear logs, see all active sessions, and provision MFA for anyone."
)

doc.sub_title("Demo Users (from LDAP)")
doc.body("These users are imported from the LDAP directory for testing:")

# User table as boxes
us = [
    ("jay", "CHANGE_ME",  "IT Security", "5 resources"),   # ⚠️ CHANGE_ME — replace before deploying
    ("luffy", "CHANGE_ME", "IT Security", "2 resources"),  # ⚠️ CHANGE_ME — replace before deploying
    ("zoro", "CHANGE_ME",  "Operations",  "2 resources"),  # ⚠️ CHANGE_ME — replace before deploying
    ("ace", "CHANGE_ME",   "Finance",     "3 resources"),  # ⚠️ CHANGE_ME — replace before deploying
]
y = doc.get_y() + 2
doc.set_font("Helvetica", "B", 9)
doc.set_fill_color(99, 102, 241)
doc.set_text_color(255, 255, 255)
doc.cell(35, 7, "Username", border=1, align="C", fill=True)
doc.cell(35, 7, "Password", border=1, align="C", fill=True)
doc.cell(40, 7, "Role", border=1, align="C", fill=True)
doc.cell(50, 7, "Access Level", border=1, align="C", fill=True)
doc.ln()
for u, pw, role, access in us:
    doc.set_font("Helvetica", "", 9)
    doc.set_fill_color(248, 248, 252)
    doc.set_text_color(40, 40, 40)
    doc.cell(35, 7, u, border=1, align="C", fill=True)
    doc.cell(35, 7, pw, border=1, align="C", fill=True)
    doc.cell(40, 7, role, border=1, align="C", fill=True)
    doc.cell(50, 7, access, border=1, align="C", fill=True)
    doc.ln()

doc.ln(5)
doc.sub_title("Resource Access by Role")
doc.body("Each role has access to specific online resources (like different rooms in a building):")
doc.bullet("Finance: Accounting Database, Document Vault, Analytics Dashboard")
doc.bullet("IT Security: DevOps Server, IT Assets, Accounting DB, Document Vault, Analytics")
doc.bullet("Operations: IT Assets, Document Vault, Analytics Dashboard")
doc.bullet("Management: Almost all resources")
doc.bullet("Admin: Everything")

# =====================================================================
# 10. ADMIN DASHBOARD WALKTHROUGH
# =====================================================================
doc.add_page()
doc.section_title("10", "Admin Dashboard Walkthrough")
doc.body("The admin dashboard has these tabs. Here is what each does:")

doc.sub_title("Users Tab")
doc.body(
    "Shows all users with their role, VPN IP, and MFA status. "
    "Click any user to see details. From the detail panel you can:"
)
doc.bullet("Grant or revoke resource access")
doc.bullet("Reset their password")
doc.bullet("View their current MFA secret key")
doc.bullet("Provision MFA for them (if they don't have it)")
doc.bullet("Reset their MFA (if they lost their phone)")
doc.bullet("Delete the user")

doc.sub_title("Sessions Tab")
doc.body(
    "Shows all currently active users -- who is logged in, their role, "
    "and how many minutes remaining before their session expires. "
    "The list refreshes automatically every 10 seconds."
)

doc.sub_title("SIEM Logs Tab")
doc.body(
    "Shows a live feed of all security events: logins, failed attempts, "
    "MFA passes/failures, access grants/denials, LDAP syncs, admin actions. "
    "You can filter by keyword and clear all logs."
)

doc.sub_title("Actions Available")
doc.bullet("Create new users")
doc.bullet("Sync LDAP users manually")
doc.bullet("Wipe all logs and invalidate non-admin sessions")
doc.bullet("View and reset MFA keys for any user")
doc.bullet("Change your own password")

# =====================================================================
# 11. TROUBLESHOOTING
# =====================================================================
doc.add_page()
doc.section_title("11", "Troubleshooting")

doc.sub_title("Admin Login Shows MFA Setup Every Time?")
doc.body("Run this command to clear the admin's MFA secret:")
doc.code_block(
    "docker exec wireguardproject-gateway-1 python /app/manage_users.py "
    "--reset-mfa admin"
)
doc.body("Then log in again and MFA will be re-provisioned.")

doc.sub_title("Database Got Corrupted?")
doc.body("Delete the database file and restart everything:")
doc.code_block("make down")
doc.code_block("rm store.db")
doc.code_block("make up")
doc.body("WARNING: This erases ALL users, passwords, MFA keys, and settings.")

doc.sub_title("Container Won't Start?")
doc.body("Check if another program is using port 8443. Change the port in docker-compose.yml if needed:")
doc.code_block(
    "# In docker-compose.yml, change:\n"
    '  "8443:8443"  ->  "9443:8443"\n'
    "# Then access at http://localhost:9443"
)

doc.sub_title("Forgot All Passwords?")
doc.body("The CLI tool can reset any user's password:")
doc.code_block(
    "docker exec wireguardproject-gateway-1 python /app/manage_users.py "
    "--change-password jay NewPass123"
)

doc.sub_title("Everything is Broken?")
doc.body(
    "The database file (store.db) is on your computer in the project folder. "
    "As long as this file exists, all users, passwords, and MFA keys are safe. "
    "You can delete and recreate the Docker containers without losing data."
)

doc.sub_title("Getting 'Preauth token not found' Error?")
doc.body(
    "This happens if the server restarted while you were in the middle of logging in. "
    "Just refresh the login page and start again. Preauth tokens now survive restarts."
)

# =====================================================================
# SAVE
# =====================================================================
doc.output(str(OUTPUT))
print(f"PDF generated: {OUTPUT}")
