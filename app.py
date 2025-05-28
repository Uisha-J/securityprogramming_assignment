import tkinter as tk
from werkzeug.security import generate_password_hash, check_password_hash
import json
import os
import math
from ctypes import memset
from datetime import datetime
import sys

# 메모리 제로화 함수
def secure_erase(buffer):
    if isinstance(buffer, bytearray):
        memset(id(buffer), 0, sys.getsizeof(buffer))

# 엔트로피 계산 함수
def calculate_entropy(password):
    charset = 0
    if any(c.islower() for c in password): charset += 26
    if any(c.isupper() for c in password): charset += 26
    if any(c.isdigit() for c in password): charset += 10
    if any(c in '!@#$%^&*()' for c in password): charset += 14
    return len(password) * math.log2(charset) if charset else 0

# JSON 데이터베이스 클래스
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

# GUI 애플리케이션 클래스
class LoginSystem(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Login v3.0")
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

        self.username = tk.StringVar()
        self.password = tk.StringVar()

        # UI 컴포넌트
        tk.Label(self.current_frame, text="Username:").grid(row=0, column=0, pady=5, sticky="e")
        tk.Entry(self.current_frame, textvariable=self.username).grid(row=0, column=1, pady=5)

        tk.Label(self.current_frame, text="Password:").grid(row=1, column=0, pady=5, sticky="e")
        tk.Entry(self.current_frame, textvariable=self.password, show="*").grid(row=1, column=1, pady=5)

        tk.Button(self.current_frame, text="Register", width=10, command=self.register).grid(row=2, column=0, pady=10)
        tk.Button(self.current_frame, text="Login", width=10, command=self.login).grid(row=2, column=1, pady=10)

        self.feedback = tk.Label(self.current_frame, text="", fg="red")
        self.feedback.grid(row=3, columnspan=2)

    def show_success_ui(self):
        self.clear_frame()
        self.current_frame = tk.Frame(self)
        self.current_frame.pack(expand=True)

        # 성공 메시지
        tk.Label(
            self.current_frame, 
            text="Login Successful!", 
            fg="green", 
            font=("Arial", 14)
        ).pack(pady=30)
        
        # 로그아웃 버튼
        tk.Button(
            self.current_frame,
            text="Logout",
            command=self.logout,
            width=10,
            bg="#4CAF50",
            fg="white"
        ).pack()

    def register(self):
        # 새 창 생성
        reg_window = tk.Toplevel(self)
        reg_window.title("Password Strength Check")
        reg_window.geometry("300x220")

        # 새로운 입력 필드
        tk.Label(reg_window, text="Username:").pack(pady=5)
        new_username = tk.StringVar()
        tk.Entry(reg_window, textvariable=new_username).pack(pady=5)

        tk.Label(reg_window, text="Password:").pack(pady=5)
        new_password = tk.StringVar()
        tk.Entry(reg_window, textvariable=new_password, show="*").pack(pady=5)

        # 엔트로피 표시 레이블
        entropy_label = tk.Label(reg_window, text="", fg="blue")
        entropy_label.pack(pady=5)

        # 에러 메시지 레이블
        error_label = tk.Label(reg_window, text="", fg="red")
        error_label.pack(pady=2)

        # 기능 버튼 프레임
        btn_frame = tk.Frame(reg_window)
        btn_frame.pack(pady=10)

        # 강도 확인 버튼
        tk.Button(btn_frame, text="Check Strength", 
                command=lambda: self.show_entropy(new_password.get(), entropy_label)).grid(row=0, column=0, padx=5)

        # 최종 등록 버튼
        tk.Button(btn_frame, text="Confirm Register", 
                command=lambda: self.finalize_registration(
                    new_username.get(), new_password.get(), reg_window, error_label, entropy_label)
                ).grid(row=0, column=1, padx=5)

    def show_entropy(self, password, label):
        entropy = calculate_entropy(password)
        status = "Strong ✅" if entropy >= 50 else "Weak ❌"
        label.config(text=f"Entropy: {entropy:.1f} ({status})", fg="blue" if entropy >= 50 else "red")

    def finalize_registration(self, username, password, window, error_label, entropy_label):
        password_buf = bytearray(password.encode('utf-8'))
        try:
            if not username or not password:
                error_label.config(text="Username and password required!")
                return

            entropy = calculate_entropy(password)
            if entropy < 50:
                error_label.config(text="Password too weak!")
                entropy_label.config(text=f"Entropy: {entropy:.1f} (Weak ❌)", fg="red")
                return

            hashed_pw = generate_password_hash(
                password,
                method='pbkdf2:sha256',
                salt_length=16
            )

            if self.db.add_user(username, hashed_pw):
                self.feedback.config(text="Registration Success!", fg="green")
                window.destroy()
            else:
                error_label.config(text="Username already exists!")
        finally:
            secure_erase(password_buf)
            self.password.set("")

    def login(self):
        username = self.username.get()
        password = self.password.get()
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
            self.password.set("")

    def logout(self):
        self.show_login_ui()

if __name__ == "__main__":
    app = LoginSystem()
    app.mainloop()
