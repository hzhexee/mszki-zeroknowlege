# d:\College\2nd Course, 4th Term\MSKZI\Cryptography\Lab14\mszki-zeroknowlege\server_gui.py

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import os
import threading
import time
import json
import random
from datetime import datetime
from server import ZKPServer

class ZeroKnowledgeServer:
    def __init__(self, root):
        self.root = root
        self.root.title("Zero Knowledge Protocol Server")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # Variables
        self.input_file_path = tk.StringVar()
        self.output_file_path = tk.StringVar()
        self.selected_protocol = tk.StringVar(value="Fiat-Shamir")
        self.progress_var = tk.DoubleVar()
        self.status_text = tk.StringVar(value="Ready")
        self.clients = {}  # Dictionary to store client information
        
        # Authentication variables
        self.auth_configs = {
            "Fiat-Shamir": {
                "n": 1223, # A simple default prime for testing
                "public_keys": {}  # Will store public keys for clients
            }
        }
        
        # Create UI elements
        self.create_widgets()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Initialize server
        self.server = ZKPServer(host='localhost', base_port=8000, num_ports=20)
        self.server.on_client_connected = self.on_client_connected
        self.server.on_message_received = self.on_message_received
        self.server.on_auth_result = self.on_auth_result
        
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left panel for existing controls
        left_panel = ttk.Frame(main_frame)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Protocol selection
        protocol_frame = ttk.LabelFrame(left_panel, text="Protocol Selection", padding="10")
        protocol_frame.pack(fill=tk.X, pady=5)
        
        protocols = ["Fiat-Shamir", "Guillou-Quisquater", "Schnorr"]
        for protocol in protocols:
            ttk.Radiobutton(protocol_frame, text=protocol, value=protocol, variable=self.selected_protocol).pack(anchor=tk.W)
        
        # File selection frame
        file_frame = ttk.LabelFrame(left_panel, text="File Selection", padding="10")
        file_frame.pack(fill=tk.X, pady=5)
        
        # Input file row
        input_file_frame = ttk.Frame(file_frame)
        input_file_frame.pack(fill=tk.X, pady=5)
        ttk.Label(input_file_frame, text="Input File:").pack(side=tk.LEFT)
        ttk.Entry(input_file_frame, textvariable=self.input_file_path, width=40).pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        ttk.Button(input_file_frame, text="Browse", command=self.browse_input_file).pack(side=tk.LEFT)
        
        # Output file row
        output_file_frame = ttk.Frame(file_frame)
        output_file_frame.pack(fill=tk.X, pady=5)
        ttk.Label(output_file_frame, text="Output File:").pack(side=tk.LEFT)
        ttk.Entry(output_file_frame, textvariable=self.output_file_path, width=40).pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        ttk.Button(output_file_frame, text="Browse", command=self.browse_output_file).pack(side=tk.LEFT)
        
        # Operation frame
        operation_frame = ttk.LabelFrame(left_panel, text="Operation", padding="10")
        operation_frame.pack(fill=tk.X, pady=5)
        
        # Operation buttons
        button_frame = ttk.Frame(operation_frame)
        button_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(button_frame, text="Encrypt", command=self.encrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Decrypt", command=self.decrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Start Server", command=self.start_server).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Stop Server", command=self.stop_server).pack(side=tk.LEFT, padx=5)
        
        # Authentication settings button (new)
        ttk.Button(button_frame, text="Auth Settings", command=self.show_auth_settings).pack(side=tk.LEFT, padx=5)
        
        # Progress frame
        progress_frame = ttk.LabelFrame(left_panel, text="Progress", padding="10")
        progress_frame.pack(fill=tk.X, pady=5)
        
        # Progress bar
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        # Status label
        ttk.Label(progress_frame, textvariable=self.status_text).pack(anchor=tk.W)
        
        # Log frame
        log_frame = ttk.LabelFrame(left_panel, text="Server Log", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Create log text widget with scrollbar
        log_scroll = ttk.Scrollbar(log_frame)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.log_text = tk.Text(log_frame, height=8, yscrollcommand=log_scroll.set)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        log_scroll.config(command=self.log_text.yview)
        
        # Connected clients (right panel)
        right_panel = ttk.Frame(main_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(10, 0))
        
        clients_frame = ttk.LabelFrame(right_panel, text="Connected Clients", padding="10")
        clients_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create Treeview for displaying clients
        columns = ('id', 'ip', 'connected_time', 'status', 'auth')
        self.clients_tree = ttk.Treeview(clients_frame, columns=columns, show='headings')
        
        # Configure columns
        self.clients_tree.heading('id', text='ID')
        self.clients_tree.column('id', width=50)
        self.clients_tree.heading('ip', text='IP Address')
        self.clients_tree.column('ip', width=120)
        self.clients_tree.heading('connected_time', text='Connected At')
        self.clients_tree.column('connected_time', width=150)
        self.clients_tree.heading('status', text='Status')
        self.clients_tree.column('status', width=80)
        self.clients_tree.heading('auth', text='Auth')
        self.clients_tree.column('auth', width=80)
        
        # Add scrollbar
        clients_scroll_y = ttk.Scrollbar(clients_frame, orient=tk.VERTICAL, command=self.clients_tree.yview)
        self.clients_tree.configure(yscroll=clients_scroll_y.set)
        
        clients_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.clients_tree.pack(fill=tk.BOTH, expand=True)
        
        # Add client control buttons
        client_actions = ttk.Frame(right_panel)
        client_actions.pack(fill=tk.X, pady=5)
        
        ttk.Button(client_actions, text="Refresh", command=self.refresh_clients).pack(side=tk.LEFT, padx=5)
        ttk.Button(client_actions, text="Disconnect Client", command=self.disconnect_client).pack(side=tk.LEFT, padx=5)
        ttk.Button(client_actions, text="Client Details", command=self.show_client_details).pack(side=tk.LEFT, padx=5)
        ttk.Button(client_actions, text="Authenticate", command=self.request_authentication).pack(side=tk.LEFT, padx=5)
        
    # Authentication methods (new)
    def show_auth_settings(self):
        """Show authentication settings dialog"""
        protocol = self.selected_protocol.get()
        
        if protocol == "Fiat-Shamir":
            # Create a popup dialog for Fiat-Shamir settings
            dialog = tk.Toplevel(self.root)
            dialog.title(f"{protocol} Settings")
            dialog.geometry("400x200")
            dialog.transient(self.root)
            dialog.grab_set()
            
            # Add settings fields
            ttk.Label(dialog, text="Modulus (n):").grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
            n_entry = ttk.Entry(dialog, width=30)
            n_entry.grid(row=0, column=1, padx=10, pady=10)
            n_entry.insert(0, str(self.auth_configs[protocol]["n"]))
            
            def save_settings():
                try:
                    n = int(n_entry.get())
                    if n < 2:
                        messagebox.showerror("Error", "Modulus must be at least 2")
                        return
                    self.auth_configs[protocol]["n"] = n
                    self.log(f"Updated {protocol} settings: n={n}")
                    dialog.destroy()
                except ValueError:
                    messagebox.showerror("Error", "Invalid input. Please enter integers only.")
            
            ttk.Button(dialog, text="Save", command=save_settings).grid(row=2, column=0, columnspan=2, pady=20)
        
        else:
            messagebox.showinfo("Info", f"Settings for {protocol} are not yet implemented")
    
    def request_authentication(self):
        """Request authentication from selected client"""
        selected = self.clients_tree.selection()
        if not selected:
            messagebox.showinfo("Info", "Please select a client")
            return
            
        client_id = selected[0]
        if client_id not in self.clients:
            messagebox.showinfo("Info", "Client no longer connected")
            return
            
        protocol = self.selected_protocol.get()
        if protocol == "Fiat-Shamir":
            # For Fiat-Shamir, we need to register client's public key
            public_key = simpledialog.askinteger("Input", "Enter client's public key (v):", parent=self.root)
            if public_key is None:  # User cancelled
                return
                
            # Store the public key for this client
            self.auth_configs[protocol]["public_keys"][client_id] = public_key
            self.log(f"Registered public key {public_key} for client {client_id}")
            
            # Send authentication request message
            client_socket = self.clients[client_id].get("socket")
            if client_socket:
                auth_request = {
                    "action": "authenticate",
                    "protocol": "fiat-shamir",
                    "n": self.auth_configs[protocol]["n"]
                }
                self.server.send_to_client(client_socket, json.dumps(auth_request))
                self.update_client_status(client_id, "Auth pending...")
        else:
            messagebox.showinfo("Info", f"Authentication with {protocol} not yet implemented")
    
    def on_auth_result(self, client_id, success):
        """Handle authentication result"""
        if client_id in self.clients:
            auth_status = "Authenticated" if success else "Auth failed"
            self.update_client_auth_status(client_id, auth_status)
            self.log(f"Client {client_id}: {auth_status}")
    
    # Client management methods
    def add_client(self, client_id, ip_address, client_socket=None, status="Connected"):
        """Add new client to the table"""
        if client_id not in self.clients:
            connected_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.clients[client_id] = {
                'ip': ip_address,
                'socket': client_socket,
                'connected_time': connected_time,
                'status': status,
                'auth': 'Not auth'
            }
            
            self.clients_tree.insert('', tk.END, iid=client_id, values=(
                client_id, ip_address, connected_time, status, 'Not auth'
            ))
            
            self.log(f"Client {client_id} ({ip_address}) connected")
    
    def update_client_status(self, client_id, new_status):
        """Update client status"""
        if client_id in self.clients:
            self.clients[client_id]['status'] = new_status
            self.clients_tree.item(client_id, values=(
                client_id, 
                self.clients[client_id]['ip'],
                self.clients[client_id]['connected_time'],
                new_status,
                self.clients[client_id]['auth']
            ))
    
    def update_client_auth_status(self, client_id, auth_status):
        """Update client authentication status"""
        if client_id in self.clients:
            self.clients[client_id]['auth'] = auth_status
            self.clients_tree.item(client_id, values=(
                client_id, 
                self.clients[client_id]['ip'],
                self.clients[client_id]['connected_time'],
                self.clients[client_id]['status'],
                auth_status
            ))
    
    def remove_client(self, client_id):
        """Удаляет клиента из таблицы"""
        if client_id in self.clients:
            ip = self.clients[client_id]['ip']
            self.clients_tree.delete(client_id)
            del self.clients[client_id]
            
            self.log(f"Client {client_id} ({ip}) disconnected")
    
    def refresh_clients(self):
        """Обновляет список клиентов"""
        # В реальной реализации здесь можно запросить актуальный список у сервера
        self.log("Refreshing client list...")
        
    def disconnect_client(self):
        """Отключает выбранного клиента"""
        selected = self.clients_tree.selection()
        if selected:
            client_id = selected[0]
            self.update_client_status(client_id, "Disconnecting...")
            # В реальной реализации здесь будет код для отключения клиента
            self.log(f"Requesting disconnect for client {client_id}...")
            
            # Имитация процесса отключения
            def simulate_disconnect():
                time.sleep(1)
                self.root.after(0, lambda: self.remove_client(client_id))
            
            threading.Thread(target=simulate_disconnect).start()
        else:
            messagebox.showinfo("Info", "Please select a client to disconnect")
    
    def show_client_details(self):
        """Показывает детальную информацию о клиенте"""
        selected = self.clients_tree.selection()
        if selected:
            client_id = selected[0]
            client_info = self.clients[client_id]
            
            details = f"Client ID: {client_id}\n"
            details += f"IP Address: {client_info['ip']}\n"
            details += f"Connected At: {client_info['connected_time']}\n"
            details += f"Status: {client_info['status']}\n"
            
            messagebox.showinfo("Client Details", details)
        else:
            messagebox.showinfo("Info", "Please select a client to view details")
    
    def browse_input_file(self):
        filename = filedialog.askopenfilename(title="Select Input File")
        if filename:
            self.input_file_path.set(filename)
            self.log("Input file selected: " + filename)
    
    def browse_output_file(self):
        filename = filedialog.asksaveasfilename(title="Select Output File")
        if filename:
            self.output_file_path.set(filename)
            self.log("Output file selected: " + filename)
    
    def log(self, message):
        self.log_text.insert(tk.END, f"{time.strftime('%H:%M:%S')} - {message}\n")
        self.log_text.see(tk.END)
    
    def encrypt(self):
        # Placeholder for encryption functionality
        if not self.input_file_path.get() or not self.output_file_path.get():
            messagebox.showerror("Error", "Please select both input and output files")
            return
            
        protocol = self.selected_protocol.get()
        self.log(f"Starting encryption with {protocol} protocol...")
        self.status_text.set(f"Encrypting with {protocol}...")
        
        # Simulate progress with a thread (will be replaced with actual implementation)
        threading.Thread(target=self.simulate_progress, args=("Encryption complete!",)).start()
    
    def decrypt(self):
        # Placeholder for decryption functionality
        if not self.input_file_path.get() or not self.output_file_path.get():
            messagebox.showerror("Error", "Please select both input and output files")
            return
            
        protocol = self.selected_protocol.get()
        self.log(f"Starting decryption with {protocol} protocol...")
        self.status_text.set(f"Decrypting with {protocol}...")
        
        # Simulate progress with a thread (will be replaced with actual implementation)
        threading.Thread(target=self.simulate_progress, args=("Decryption complete!",)).start()
    
    def start_server(self):
        protocol = self.selected_protocol.get()
        self.log(f"Starting server with {protocol} protocol...")
        self.status_text.set(f"Server running with {protocol}...")
        
        self.server.start()
        self.server_status_label.config(text="Server: Running")
        self.start_server_btn.config(state="disabled")
        self.stop_server_btn.config(state="normal")
        self.log_message(f"Server started on ports {self.server.base_port}-{self.server.base_port + self.server.num_ports - 1}")
    
    def stop_server(self):
        self.log("Stopping server...")
        self.status_text.set("Server stopped")
        
        self.server.stop()
        self.server_status_label.config(text="Server: Not Running")
        self.start_server_btn.config(state="normal")
        self.stop_server_btn.config(state="disabled")
        self.log_message("Server stopped")
        
        # Отключаем всех клиентов при остановке сервера
        for client_id in list(self.clients.keys()):
            self.remove_client(client_id)
    
    def on_client_connected(self, client_socket, address, port):
        client_id = f"{address[0]}:{address[1]}"
        self.log_message(f"Client connected from {address} on port {port}")
        
        # Add client to the UI
        self.root.after(0, lambda: self.add_client(client_id, address[0], client_socket))
    
    def on_message_received(self, message, client_socket, address, port):
        client_id = f"{address[0]}:{address[1]}"
        self.log_message(f"Message from {address} on port {port}: {message}")
        
        # Try to parse JSON messages
        try:
            msg_data = json.loads(message)
            if msg_data.get("action") == "auth_response":
                # Handle authentication response
                protocol = msg_data.get("protocol")
                result = msg_data.get("result")
                
                if protocol and result:
                    success = (result == "success")
                    self.root.after(0, lambda: self.update_client_auth_status(
                        client_id, "Authenticated" if success else "Auth failed"))
                    
                    return json.dumps({"status": "ok"})
        except (json.JSONDecodeError, TypeError):
            pass  # Not JSON or not properly formatted
            
        # Default response
        return "Message received"
    
    def log_message(self, message):
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)
    
    def simulate_progress(self, completion_message):
        # This is just a placeholder to simulate progress
        # Will be replaced with actual implementation later
        self.progress_var.set(0)
        for i in range(101):
            time.sleep(0.05)  # Simulating work
            self.progress_var.set(i)
            if i % 10 == 0:
                self.log(f"Progress: {i}%")
        self.status_text.set(completion_message)
        self.log(completion_message)
    
    def on_closing(self):
        # Handle window closing
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            if hasattr(self, 'server'):
                self.server.stop()
            self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = ZeroKnowledgeServer(root)
    root.mainloop()