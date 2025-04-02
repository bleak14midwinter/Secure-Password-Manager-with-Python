import tkinter as tk
from tkinter import ttk, messagebox
import json
import os
from cryptography.fernet import Fernet
import re
import hashlib
import base64
import secrets
import string

class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("1000x500")
        
        self.center_window(self.root)
        
        self.master_key = None
        self.file_cipher = None
        self.show_login_window()

    def center_window(self, window):
        window.update_idletasks()
        width = window.winfo_width()
        height = window.winfo_height()
        x = (window.winfo_screenwidth() // 2) - (width // 2)
        y = (window.winfo_screenheight() // 2) - (height // 2)
        window.geometry(f'{width}x{height}+{x}+{y}')

    def show_login_window(self):
        self.login_window = tk.Toplevel(self.root)
        self.login_window.title("Master Password")
        self.login_window.geometry("300x150")
        self.login_window.resizable(False, False)
        
        self.center_window(self.login_window)
        self.center_window(self.root)
        self.login_window.attributes('-topmost', True)
        
        self.login_window.protocol("WM_DELETE_WINDOW", self.on_login_close)
        
        ttk.Label(self.login_window, text="Enter Master Password:").pack(pady=10)
        
        self.master_entry = ttk.Entry(self.login_window, show="*")
        self.master_entry.pack(pady=5)
        self.master_entry.focus_set()
        
        ttk.Button(self.login_window, text="Login", command=self.verify_master_password).pack(pady=10)
        
        self.login_window.grab_set()
        self.master_entry.bind("<Return>", lambda e: self.verify_master_password())

    def on_login_close(self):
        self.login_window.destroy()
        self.root.destroy()

    def verify_master_password(self):
        master_password = self.master_entry.get()
        if not master_password:
            messagebox.showerror("Error", "Master password cannot be empty!")
            return
            
        self.master_key = base64.urlsafe_b64encode(hashlib.sha256(master_password.encode()).digest())
        self.file_cipher = Fernet(self.load_or_generate_file_key())
        self.passwords = self.load_passwords()
        
        if self.passwords is not None:
            self.login_window.destroy()
            self.create_widgets()
        else:
            messagebox.showerror("Error", "Incorrect master password or corrupted data!")
            self.master_entry.delete(0, tk.END)

    def load_or_generate_file_key(self):
        if os.path.exists("filekey.key"):
            with open("filekey.key", "rb") as key_file:
                return key_file.read()
        else:
            key = Fernet.generate_key()
            with open("filekey.key", "wb") as key_file:
                key_file.write(key)
            return key

    def load_passwords(self):
        try:
            if os.path.exists("passwords.json"):
                with open("passwords.json", "rb") as file:
                    encrypted_data = file.read()
                    decrypted_data = self.file_cipher.decrypt(encrypted_data)
                    data = json.loads(decrypted_data.decode())
                    
                    cipher = Fernet(self.master_key)
                    for entry in data:
                        entry['password'] = cipher.decrypt(entry['password'].encode()).decode()
                    return data
            return []
        except Exception as e:
            print(f"Error loading passwords: {e}")
            return None

    def save_passwords(self):
        if self.master_key is None or self.file_cipher is None:
            return
            
        cipher = Fernet(self.master_key)
        encrypted_data = []
        for entry in self.passwords:
            encrypted_entry = entry.copy()
            encrypted_entry['password'] = cipher.encrypt(entry['password'].encode()).decode()
            encrypted_data.append(encrypted_entry)
        
        json_data = json.dumps(encrypted_data).encode()
        encrypted_file = self.file_cipher.encrypt(json_data)
        
        with open("passwords.json", "wb") as file:
            file.write(encrypted_file)

    def generate_password(self):
        alphabet = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(alphabet) for _ in range(16))
        password = (secrets.choice(string.ascii_uppercase) + 
                   secrets.choice(string.ascii_lowercase) + 
                   secrets.choice(string.digits) + 
                   secrets.choice(string.punctuation) + 
                   password)[:16]
        password_list = list(password)
        secrets.SystemRandom().shuffle(password_list)
        password = ''.join(password_list)
        
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        self.analyze_password(None)

    def create_widgets(self):
        input_frame = ttk.Frame(self.root, padding="10")
        input_frame.grid(row=0, column=0, sticky="ew")

        ttk.Label(input_frame, text="Website:").grid(row=0, column=0, padx=5)
        self.website_entry = ttk.Entry(input_frame, width=25)
        self.website_entry.grid(row=0, column=1, padx=5)

        ttk.Label(input_frame, text="Username:").grid(row=0, column=2, padx=5)
        self.username_entry = ttk.Entry(input_frame, width=25)
        self.username_entry.grid(row=0, column=3, padx=5)

        ttk.Label(input_frame, text="Password:").grid(row=0, column=4, padx=5)
        self.password_entry = ttk.Entry(input_frame, width=25)
        self.password_entry.grid(row=0, column=5, padx=5)
        self.password_entry.bind('<KeyRelease>', self.analyze_password)

        self.strength_label = ttk.Label(input_frame, text="Strength: N/A")
        self.strength_label.grid(row=0, column=6, padx=5)

        ttk.Button(input_frame, text="Add", command=self.add_password).grid(row=0, column=7, padx=5)
        ttk.Button(input_frame, text="Generate", command=self.generate_password).grid(row=0, column=8, padx=5)

        tree_frame = ttk.Frame(self.root, padding="10")
        tree_frame.grid(row=1, column=0, sticky="nsew")

        self.tree = ttk.Treeview(tree_frame, columns=("Website", "Username", "Password"), show="headings")
        self.tree.heading("Website", text="Website")
        self.tree.heading("Username", text="Username")
        self.tree.heading("Password", text="Password")
        self.tree.column("Website", width=300)
        self.tree.column("Username", width=300)
        self.tree.column("Password", width=300)
        self.tree.pack(fill="both", expand=True)

        btn_frame = ttk.Frame(self.root, padding="10")
        btn_frame.grid(row=2, column=0, sticky="ew")

        self.hide_btn = ttk.Button(btn_frame, text="Hide Passwords", command=self.toggle_passwords)
        self.hide_btn.grid(row=0, column=0, padx=5)

        ttk.Button(btn_frame, text="Delete Selected", command=self.delete_password).grid(row=0, column=1, padx=5)

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)

        self.show_passwords = True
        self.update_treeview()

    def analyze_password(self, event):
        password = self.password_entry.get()
        strength = self.check_password_strength(password)
        self.strength_label.config(text=f"Strength: {strength}")

    def check_password_strength(self, password):
        if len(password) == 0:
            return "N/A"
        
        score = 0
        if len(password) >= 8:
            score += 1
        if re.search(r"[A-Z]", password):
            score += 1
        if re.search(r"[a-z]", password):
            score += 1
        if re.search(r"[0-9]", password):
            score += 1
        if re.search(r"[!@#$%^&*]", password):
            score += 1

        if score <= 2:
            return "Weak"
        elif score <= 4:
            return "Medium"
        else:
            return "Strong"

    def add_password(self):
        website = self.website_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()

        if website and username and password:
            self.passwords.append({
                "website": website,
                "username": username,
                "password": password
            })
            self.save_passwords()
            self.update_treeview()
            self.website_entry.delete(0, tk.END)
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
            self.strength_label.config(text="Strength: N/A")
        else:
            messagebox.showwarning("Warning", "All fields are required!")

    def toggle_passwords(self):
        self.show_passwords = not self.show_passwords
        self.hide_btn.config(text="Show Passwords" if not self.show_passwords else "Hide Passwords")
        self.update_treeview()

    def update_treeview(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        for entry in self.passwords:
            password = "**********" if not self.show_passwords else entry["password"]
            self.tree.insert("", "end", values=(entry["website"], entry["username"], password))

    def delete_password(self):
        selected = self.tree.selection()
        if selected:
            if messagebox.askyesno("Confirm", "Delete selected entry?"):
                index = self.tree.index(selected[0])
                del self.passwords[index]
                self.save_passwords()
                self.update_treeview()
        else:
            messagebox.showwarning("Warning", "Please select an entry to delete!")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()
    
