import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import threading
import rsa

from main import load_config, generate_rsa_keys, send_public_key, receive_public_key, encrypt_file, decrypt_file, send_file, receive_file

class SecureFileShareApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Share")
        self.root.geometry("500x400")
        
        self.config = load_config()
        self.username = ""
        self.role = ""
        self.private_key = None
        self.public_key = None
        
        self.create_welcome_screen()
    
    def create_welcome_screen(self):
        self.clear_window()
        
        tk.Label(self.root, text="Secure File Sharing", font=("Arial", 16)).pack(pady=20)
        
        tk.Label(self.root, text="Username:").pack()
        self.username_entry = tk.Entry(self.root)
        self.username_entry.pack()
        
        tk.Label(self.root, text="Role:").pack()
        self.role_var = tk.StringVar(value="receiver")
        tk.Radiobutton(self.root, text="Sender", variable=self.role_var, value="sender").pack()
        tk.Radiobutton(self.root, text="Receiver", variable=self.role_var, value="receiver").pack()
        
        tk.Button(self.root, text="Continue", command=self.setup_role).pack(pady=20)
    
    def setup_role(self):
        self.username = self.username_entry.get()
        self.role = self.role_var.get()
        
        if not self.username:
            messagebox.showerror("Error", "Please enter username")
            return
        
        try:
            self.private_key, self.public_key = generate_rsa_keys(self.username)
            
            if self.role == "sender":
                self.create_sender_interface()
            else:
                self.create_receiver_interface()
        except Exception as e:
            messagebox.showerror("Error", f"Key generation failed: {str(e)}")
    
    def create_sender_interface(self):
        self.clear_window()
        
        tk.Label(self.root, text=f"Sender: {self.username}").pack()
        
        tk.Label(self.root, text="Recipient username:").pack()
        self.recipient_entry = tk.Entry(self.root)
        self.recipient_entry.pack()
        
        tk.Label(self.root, text="Recipient IP:").pack()
        self.ip_entry = tk.Entry(self.root)
        self.ip_entry.insert(0, "127.0.0.1")
        self.ip_entry.pack()
        
        tk.Label(self.root, text="Port:").pack()
        self.port_entry = tk.Entry(self.root)
        self.port_entry.insert(0, "5001")
        self.port_entry.pack()
        
        tk.Label(self.root, text="File:").pack()
        self.file_path = tk.StringVar()
        tk.Entry(self.root, textvariable=self.file_path, state='readonly').pack()
        tk.Button(self.root, text="Browse", command=self.browse_file).pack()
        
        self.status = tk.Label(self.root, text="Ready")
        self.status.pack()
        
        tk.Button(self.root, text="Send Public Key", command=self.do_send_pubkey).pack(pady=5)
        tk.Button(self.root, text="Send File", command=self.do_send_file).pack(pady=5)
        tk.Button(self.root, text="Back", command=self.create_welcome_screen).pack(pady=5)
    
    def create_receiver_interface(self):
        self.clear_window()
        
        tk.Label(self.root, text=f"Receiver: {self.username}").pack()
        
        tk.Label(self.root, text="Sender username:").pack()
        self.sender_entry = tk.Entry(self.root)
        self.sender_entry.pack()
        
        tk.Label(self.root, text="Port:").pack()
        self.port_entry = tk.Entry(self.root)
        self.port_entry.insert(0, "5001")
        self.port_entry.pack()
        
        self.status = tk.Label(self.root, text="Ready")
        self.status.pack()
        
        tk.Button(self.root, text="Receive Public Key", command=self.do_receive_pubkey).pack(pady=5)
        tk.Button(self.root, text="Receive File", command=self.do_receive_file).pack(pady=5)
        tk.Button(self.root, text="Decrypt File", command=self.do_decrypt_file).pack(pady=5)
        tk.Button(self.root, text="Back", command=self.create_welcome_screen).pack(pady=5)
    
    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_path.set(filename)
    
    def do_send_pubkey(self):
        recipient = self.recipient_entry.get()
        ip = self.ip_entry.get()
        port = self.port_entry.get()
        
        if not all([recipient, ip, port]):
            messagebox.showerror("Error", "Please fill all fields")
            return
        
        try:
            port = int(port)
            self.status.config(text="Sending public key...")
            threading.Thread(target=lambda: self._send_pubkey(ip, port)).start()
        except ValueError:
            messagebox.showerror("Error", "Invalid port number")
    
    def _send_pubkey(self, ip, port):
        try:
            send_public_key(self.username, ip, port)
            self.status.config(text="Public key sent")
        except Exception as e:
            self.status.config(text=f"Error: {str(e)}")
    
    def do_send_file(self):
        recipient = self.recipient_entry.get()
        ip = self.ip_entry.get()
        port = self.port_entry.get()
        file_path = self.file_path.get()
        
        if not all([recipient, ip, port, file_path]):
            messagebox.showerror("Error", "Please fill all fields and select file")
            return
        
        pubkey_file = f"{recipient}_public.pem"
        if not os.path.exists(pubkey_file):
            messagebox.showerror("Error", "Recipient public key not found")
            return
        
        try:
            port = int(port)
            with open(pubkey_file, "rb") as f:
                pubkey = rsa.PublicKey.load_pkcs1(f.read())
            
            self.status.config(text="Encrypting and sending file...")
            threading.Thread(target=lambda: self._send_file(file_path, pubkey, ip, port)).start()
        except Exception as e:
            self.status.config(text=f"Error: {str(e)}")
    
    def _send_file(self, file_path, pubkey, ip, port):
        try:
            encrypt_file(file_path, pubkey)
            send_file(file_path + ".enc", ip, port)
            send_file("aes_key.enc", ip, port)
            self.status.config(text="File sent successfully")
        except Exception as e:
            self.status.config(text=f"Error: {str(e)}")
    
    def do_receive_pubkey(self):
        sender = self.sender_entry.get()
        port = self.port_entry.get()
        
        if not all([sender, port]):
            messagebox.showerror("Error", "Please fill all fields")
            return
        
        try:
            port = int(port)
            self.status.config(text="Waiting for public key...")
            threading.Thread(target=lambda: self._receive_pubkey(port)).start()
        except ValueError:
            messagebox.showerror("Error", "Invalid port number")
    
    def _receive_pubkey(self, port):
        try:
            receive_public_key(self.sender_entry.get(), port)
            self.status.config(text="Public key received")
        except Exception as e:
            self.status.config(text=f"Error: {str(e)}")
    
    def do_receive_file(self):
        port = self.port_entry.get()
        
        if not port:
            messagebox.showerror("Error", "Please enter port")
            return
        
        try:
            port = int(port)
            self.status.config(text="Waiting for files...")
            threading.Thread(target=lambda: self._receive_file(port)).start()
        except ValueError:
            messagebox.showerror("Error", "Invalid port number")
    
    def _receive_file(self, port):
        try:
            receive_file(port, "received.enc")
            receive_file(port, "aes_key.enc")
            self.status.config(text="Files received")
        except Exception as e:
            self.status.config(text=f"Error: {str(e)}")
    
    def do_decrypt_file(self):
        if not (os.path.exists("received.enc") and os.path.exists("aes_key.enc")):
            messagebox.showerror("Error", "No files to decrypt")
            return
        
        self.status.config(text="Decrypting...")
        threading.Thread(target=self._decrypt_file).start()
    
    def _decrypt_file(self):
        try:
            decrypt_file(self.private_key, "received.enc")
            self.status.config(text="File decrypted")
        except Exception as e:
            self.status.config(text=f"Error: {str(e)}")
    
    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureFileShareApp(root)
    root.mainloop()