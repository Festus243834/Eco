from werkzeug.security import generate_password_hash
import sqlite3

username = "admin"
password = "admin123"
full_name = "System Administrator"
email = "admin@ecocycle.com"

conn = sqlite3.connect('ecocycle.db')
password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
conn.execute("INSERT INTO admins (username, password_hash, full_name, email) VALUES (?, ?, ?, ?)",
             (username, password_hash, full_name, email))
conn.commit()
conn.close()

print("✅ Admin created successfully! Username:", username, "Password:", password)
