import os
import sys
import time
import json
import logging
from typing import Dict, Any, Optional
import argparse

# Add project root to path for imports
sys.path.append(os.path.abspath(os.path.dirname(os.path.dirname(__file__))))
from client import (
    connect_to_server, 
    send_to_server, 
    receive_from_server, 
    disconnect_from_server, 
    start_authentication
)
from fiatshamir.authentication import generate_fiat_shamir_keys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('ZKP-Client-UI')

class ZKPClientConsole:
    def __init__(self):
        """Initialize the ZKP client console"""
        self.connected = False
        self.authenticated = False
        self.host = 'localhost'
        self.port = 8000
        self.keys = {
            'private_key': None,
            'public_key': None,
            'n': 1223  # Default modulus
        }

    def display_menu(self):
        """Display the main menu"""
        print("\n" + "="*50)
        print(" Zero-Knowledge Proof Client ".center(50, "="))
        print("="*50)
        print("1. Connect to server")
        print("2. Generate keys")
        print("3. Authenticate")
        print("4. Send message")
        print("5. Receive message")
        print("6. Disconnect")
        print("7. Change connection settings")
        print("8. Show current status")
        print("0. Exit")
        print("="*50)
        
        if self.connected:
            status = "Connected"
            if self.authenticated:
                status += " (Authenticated)"
        else:
            status = "Disconnected"
        
        print(f"Status: {status} | Server: {self.host}:{self.port}")
        print("="*50)
        
        return input("Enter your choice: ")

    def connect(self):
        """Connect to the server"""
        if self.connected:
            print("Already connected to server")
            return
            
        print(f"\nConnecting to server at {self.host}:{self.port}...")
        if connect_to_server(self.host, self.port):
            self.connected = True
            print("Connection established successfully")
        else:
            print("Failed to connect to server")

    def generate_keys(self):
        """Generate keys for authentication"""
        n = int(input("Enter modulus (n) [default=1223]: ") or "1223")
        self.keys['n'] = n
        
        print("\nGenerating Fiat-Shamir keys...")
        private_key, public_key = generate_fiat_shamir_keys(n)
        
        self.keys['private_key'] = private_key
        self.keys['public_key'] = public_key
        
        print(f"Keys generated successfully:")
        print(f"Private key (s): {private_key}")
        print(f"Public key (v): {public_key}")
        print(f"Modulus (n): {n}")

    def authenticate(self):
        """Authenticate with the server"""
        if not self.connected:
            print("Not connected to server. Please connect first.")
            return
            
        if self.authenticated:
            print("Already authenticated")
            return
            
        if not self.keys['private_key']:
            print("No keys available. Please generate keys first.")
            return
            
        print("\nStarting Fiat-Shamir authentication...")
        result = start_authentication(
            protocol='fiat-shamir', 
            private_key=self.keys['private_key'], 
            n=self.keys['n']
        )
        
        if result:
            self.authenticated = True
            print("Authentication successful")
        else:
            print("Authentication failed")

    def send_message(self):
        """Send a message to the server"""
        if not self.connected:
            print("Not connected to server. Please connect first.")
            return
            
        message = input("Enter message to send: ")
        if send_to_server(message):
            print("Message sent successfully")
        else:
            print("Failed to send message")

    def receive_message(self):
        """Receive a message from the server"""
        if not self.connected:
            print("Not connected to server. Please connect first.")
            return
            
        print("Waiting for server message...")
        message = receive_from_server()
        
        if message:
            print(f"Received: {message}")
        else:
            print("Failed to receive message")

    def disconnect(self):
        """Disconnect from the server"""
        if not self.connected:
            print("Not connected to server")
            return
            
        disconnect_from_server()
        self.connected = False
        self.authenticated = False
        print("Disconnected from server")

    def change_settings(self):
        """Change connection settings"""
        print("\nCurrent settings:")
        print(f"Host: {self.host}")
        print(f"Port: {self.port}")
        
        new_host = input("Enter new host (leave blank to keep current): ")
        if new_host:
            self.host = new_host
            
        try:
            new_port = input("Enter new port (leave blank to keep current): ")
            if new_port:
                self.port = int(new_port)
        except ValueError:
            print("Invalid port number. Using previous value.")
            
        print(f"Updated settings: {self.host}:{self.port}")

    def show_status(self):
        """Show current client status"""
        print("\nCurrent Client Status:")
        print(f"Connected: {self.connected}")
        print(f"Authenticated: {self.authenticated}")
        print(f"Server: {self.host}:{self.port}")
        print("\nKeys:")
        print(f"Private key: {self.keys['private_key']}")
        print(f"Public key: {self.keys['public_key']}")
        print(f"Modulus (n): {self.keys['n']}")

    def run(self):
        """Run the client console UI"""
        print("Welcome to Zero-Knowledge Proof Client")
        
        while True:
            choice = self.display_menu()
            
            try:
                if choice == '1':
                    self.connect()
                elif choice == '2':
                    self.generate_keys()
                elif choice == '3':
                    self.authenticate()
                elif choice == '4':
                    self.send_message()
                elif choice == '5':
                    self.receive_message()
                elif choice == '6':
                    self.disconnect()
                elif choice == '7':
                    self.change_settings()
                elif choice == '8':
                    self.show_status()
                elif choice == '0':
                    if self.connected:
                        self.disconnect()
                    print("Exiting client. Goodbye!")
                    break
                else:
                    print("Invalid choice. Please try again.")
            
            except Exception as e:
                print(f"Error: {e}")
                logger.exception("Error in client UI")
            
            # Pause to let user read the output
            time.sleep(1)

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='ZKP Client')
    parser.add_argument('-H', '--host', default='localhost', help='Server host (default: localhost)')
    parser.add_argument('-p', '--port', type=int, default=8000, help='Server port (default: 8000)')
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    
    client_ui = ZKPClientConsole()
    client_ui.host = args.host
    client_ui.port = args.port
    
    try:
        client_ui.run()
    except KeyboardInterrupt:
        print("\nClient terminated by user")
        if client_ui.connected:
            client_ui.disconnect()
    except Exception as e:
        logger.exception("Unhandled exception")
        print(f"An error occurred: {e}")
