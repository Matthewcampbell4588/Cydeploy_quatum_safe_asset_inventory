import tkinter as tk
from tkinter import messagebox
import auth_client

def start_GUI(sock, client_dilithium_priv, shared_secret, server_dilithium_pub):
    def login_attempt():
        result = auth_client.login(sock, shared_secret, server_dilithium_pub)
        if result:
            login_window.destroy()
            launch_main_app()
        else:
            messagebox.showerror("Login Failed", "Authentication failed or access denied.")

    def launch_main_app():
        app = tk.Tk()
        app.title("Secure Chat")
        app.geometry("400x300")
        label = tk.Label(app, text="Welcome to the secure session!", font=('Arial', 16))
        label.pack(pady=20)
        app.mainloop()

    login_window = tk.Tk()
    login_window.title("Secure Login")
    login_window.geometry("300x200")

    tk.Label(login_window, text="Username:").pack()
    username_entry = tk.Entry(login_window)
    username_entry.pack()

    tk.Label(login_window, text="Password:").pack()
    password_entry = tk.Entry(login_window, show="*")
    password_entry.pack()

    def on_submit():
        auth_client.input = lambda _: username_entry.get() if _.lower().startswith('username') else password_entry.get()
        login_attempt()

    tk.Button(login_window, text="Login", command=on_submit).pack(pady=10)
    login_window.mainloop()
