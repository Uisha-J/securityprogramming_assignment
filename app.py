import tkinter as tk
from werkzeug.security import generate_password_hash, check_password_hash
import json
import os
import math
from ctypes import memset
from datetime import datetime
import sys
import string

def secure_erase(buffer):
    if isinstance(buffer, bytearray):
        for i in range(len(buffer)):
            buffer[i] = 0

def calculate_shannon_entropy(password):
    # 섀년 엔트로피 계산
    freq = {}
    for c in password:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    length = len(password)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy * length  # 전체 비트 엔트로피

def calculate_entropy(password):
    charset = 0
    if any(c.islower() for c in password): charset += 26
    if any(c.isupper() for c in password): charset += 26
    if any(c.isdigit() for c in password): charset += 10
    if any(c in '!@#$%^&*()' for c in password): charset += 14
    return len(password) * math.log2(charset) if charset else 0

def is_valid_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if not any(c.islower() for c in password):
        return False, "Password must include a lowercase letter."
    if not any(c.isupper() for c in password):
        return False, "Password must include an uppercase letter."
    if not any(c in string.punctuation for c in password):
        return False, "Password must include a special character."
    return True, ""

class JSONDatabase:
    def __init__(self, filename='users.json'):
        self.filename = filename
        self._initialize_db()

    def _initialize_db(self):
        if not os.path.exists(self.filename):
            with open(self.filename, 'w') as f:
                json.dump({'users': []}, f)

    def add_user(self, username, password_hash):
        with open(self.filename, 'r+') as f:
            data = json.load(f)
            if any(user['username'] == username for user in data['users']):
                return False
            data['users'].append({
                'username': username,
                'password_hash': password_hash,
                'created_at': datetime.now().isoformat()
            })
            f.seek(0)
            json.dump(data, f, indent=2)
        return True

class LoginSystem(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Login v3.2")
        self.geometry("350x200")
        self.resizable(False, False)
        self.db = JSONDatabase()
        self.current_frame = None
        self.show_login_ui()

    def clear_frame(self):
        if self.current_frame:
            self.current_frame.destroy()

    def show_login_ui(self):
        self.clear_frame()
        self.current_frame = tk.Frame(self)
        self.current_frame.pack(expand=True)

        username_var = tk.StringVar()
        password_var = tk.StringVar()

        tk.Label(self.current_frame, text="Username:").grid(row=0, column=0, pady=5, sticky="e")
        tk.Entry(self.current_frame, textvariable=username_var).grid(row=0, column=1, pady=5)

        tk.Label(self.current_frame, text="Password:").grid(row=1, column=0, pady=5, sticky="e")
        tk.Entry(self.current_frame, textvariable=password_var, show="*").grid(row=1, column=1, pady=5)

        tk.Button(self.current_frame, text="Register", width=10,
                command=self.register).grid(row=2, column=0, pady=10)
        tk.Button(self.current_frame, text="Login", width=10,
                command=lambda: self.login(username_var.get(), password_var.get())).grid(row=2, column=1, pady=10)

        self.feedback = tk.Label(self.current_frame, text="", fg="red")
        self.feedback.grid(row=3, columnspan=2)

    def show_success_ui(self):
        self.clear_frame()
        self.current_frame = tk.Frame(self)
        self.current_frame.pack(expand=True)

        tk.Label(self.current_frame, text="Login Successful!", 
                fg="green", font=("Arial", 14)).pack(pady=30)
        tk.Button(self.current_frame, text="Logout",
                command=self.logout, width=10, bg="#4CAF50", fg="white").pack()

    def register(self):
        reg_window = tk.Toplevel(self)
        reg_window.title("Password Strength Check")
        reg_window.geometry("300x300")

        tk.Label(reg_window, text="Username:").pack(pady=5)
        new_username = tk.StringVar()
        tk.Entry(reg_window, textvariable=new_username).pack(pady=5)

        tk.Label(reg_window, text="Password:").pack(pady=5)
        new_password = tk.StringVar()
        tk.Entry(reg_window, textvariable=new_password, show="*").pack(pady=5)
        
        charset_label = tk.Label(reg_window, text="", fg="blue")
        charset_label.pack(pady=5)
        shannon_label = tk.Label(reg_window, text="", fg="purple")
        shannon_label.pack(pady=5)
        error_label = tk.Label(reg_window, text="", fg="red")
        error_label.pack(pady=2)

        btn_frame = tk.Frame(reg_window)
        btn_frame.pack(pady=10)

        tk.Button(btn_frame, text="Check Strength", 
                command=lambda: self.show_entropy(
                    new_password.get(), 
                    charset_label, 
                    shannon_label
                )).grid(row=0, column=0, padx=5)
        tk.Button(btn_frame, text="Confirm Register", 
                command=lambda: self.finalize_registration(
                    new_username.get(), new_password.get(), reg_window, error_label, charset_label, shannon_label)
                ).grid(row=0, column=1, padx=5)

    def show_entropy(self, password, charset_label, shannon_label):
        # 문자 집합 엔트로피
        charset_entropy = calculate_entropy(password)
        status_charset = "Strong ✅" if charset_entropy >= 50 else "Weak ❌"
        charset_label.config(
            text=f"Charset Entropy: {charset_entropy:.1f} ({status_charset})",
            fg="blue" if charset_entropy >= 50 else "red"
        )
        
        # 샤논 엔트로피
        shannon_entropy = calculate_shannon_entropy(password)
        status_shannon = "Strong ✅" if shannon_entropy >= 24 else "Weak ❌"
        shannon_label.config(
            text=f"Shannon Entropy: {shannon_entropy:.1f} ({status_shannon})",
            fg="green" if shannon_entropy >= 24 else "red"
        )

    def finalize_registration(self, username, password, window, error_label, charset_label, shannon_label):
        password_buf = bytearray(password.encode('utf-8'))
        try:
            if not username or not password:
                error_label.config(text="Username and password required!")
                return

            valid, msg = is_valid_password(password)
            if not valid:
                error_label.config(text=msg)
                return
        
            charset_entropy = calculate_entropy(password)
            shannon_entropy = calculate_shannon_entropy(password)

            entropy = calculate_entropy(password)
            if charset_entropy < 50 or shannon_entropy < 24:
                error_label.config(text="Password entropy too low!")
                charset_label.config(fg="red")
                shannon_label.config(fg="red")
                return

            hashed_pw = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

            if self.db.add_user(username, hashed_pw):
                window.destroy()  # 먼저 창 닫기
                self.feedback.config(text="Registration Success!", fg="green")
            else:
                error_label.config(text="Username already exists!")
        except Exception as e:
            error_label.config(text=f"Error: {str(e)}")
        finally:
            secure_erase(password_buf)

    def login(self, username, password):
        password_buf = bytearray(password.encode('utf-8'))
        try:
            with open(self.db.filename) as f:
                users = json.load(f)['users']
            target_user = next((u for u in users if u['username'] == username), None)
            if target_user and check_password_hash(target_user['password_hash'], password):
                self.show_success_ui()
            else:
                self.feedback.config(text="Invalid credentials!")
        finally:
            secure_erase(password_buf)

    def logout(self):
        self.show_login_ui()

if __name__ == "__main__":
    app = LoginSystem()
    app.mainloop()
