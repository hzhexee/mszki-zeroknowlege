# d:\College\2nd Course, 4th Term\MSKZI\Cryptography\Lab14\mszki-zeroknowlege\server.py

import sys
import os
import socket
import threading
import logging
import random
import json
from typing import List, Optional, Callable
from serverAuth import fiat_shamir_verify  # Исправлен импорт path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('ZKP-Server')

class ZKPServer:
    def __init__(self, host: str = 'localhost', base_port: int = 8000, num_ports: int = 3):
        """
        Initialize the ZKP server
        
        Args:
            host: Host address to bind to
            base_port: Starting port number
            num_ports: Number of consecutive ports to listen on
        """
        self.host = host
        self.base_port = base_port
        self.num_ports = num_ports
        self.servers: List[socket.socket] = []
        self.client_handlers: List[threading.Thread] = []
        self.running = False
        self.on_client_connected: Optional[Callable] = None
        self.on_message_received: Optional[Callable] = None
        self.on_auth_result: Optional[Callable] = None  # Добавлен callback для результатов аутентификации
        self.client_sessions = {}  # Store session data for clients
        self.auth_challenges = {}  # Store authentication challenges
        
    def start(self):
        """Start the server on multiple ports"""
        self.running = True
        
        for port_offset in range(self.num_ports):
            port = self.base_port + port_offset
            server_thread = threading.Thread(
                target=self._run_server, 
                args=(port,),
                daemon=True
            )
            server_thread.start()
            logger.info(f"Server started on port {port}")
        
        logger.info(f"Server is running on {self.host} with {self.num_ports} ports starting from {self.base_port}")
    
    def _run_server(self, port):
        """Run server on specific port"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server.bind((self.host, port))
            server.listen(5)
            self.servers.append(server)
            
            logger.info(f"Listening on {self.host}:{port}")
            
            while self.running:
                try:
                    client_socket, address = server.accept()
                    logger.info(f"Client connected from {address} on port {port}")
                    
                    # Notify about connection if callback is set
                    if self.on_client_connected:
                        self.on_client_connected(client_socket, address, port)
                    
                    # Start client handler
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, address, port),
                        daemon=True
                    )
                    client_thread.start()
                    self.client_handlers.append(client_thread)
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"Error accepting connection on port {port}: {e}")
            
        except Exception as e:
            logger.error(f"Failed to start server on port {port}: {e}")
        finally:
            if server in self.servers:
                self.servers.remove(server)
    
    def _handle_client(self, client_socket, address, port):
        """Handle communication with a connected client"""
        client_id = f"{address[0]}:{address[1]}"
        self.client_sessions[client_id] = {
            "socket": client_socket,
            "address": address,
            "port": port,
            "authenticated": False,
            "auth_stage": 0,
            "auth_data": {}
        }
        
        try:
            while self.running:
                data = client_socket.recv(1024)
                if not data:
                    logger.info(f"Client {address} disconnected")
                    break
                    
                message = data.decode('utf-8')
                logger.info(f"Received from {address} on port {port}: {message}")
                
                # Handle Fiat-Shamir authentication protocol messages
                if self.client_sessions[client_id]["auth_stage"] > 0:
                    self._handle_auth_message(client_id, message)
                    continue
                
                # Try to parse message as JSON
                try:
                    msg_data = json.loads(message)
                    if msg_data.get("action") == "auth_request" and msg_data.get("protocol") == "fiat-shamir":
                        # Initialize Fiat-Shamir authentication
                        self._start_fiat_shamir_auth(client_id, msg_data)
                        continue
                except (json.JSONDecodeError, TypeError):
                    pass  # Not JSON or not properly formatted
                
                # Process message if callback is set
                if self.on_message_received:
                    response = self.on_message_received(message, client_socket, address, port)
                    if response:
                        client_socket.send(response.encode('utf-8'))
                
        except Exception as e:
            logger.error(f"Error handling client {address} on port {port}: {e}")
        finally:
            if client_id in self.client_sessions:
                del self.client_sessions[client_id]
            client_socket.close()
            logger.info(f"Connection closed with {address} on port {port}")
    
    def _start_fiat_shamir_auth(self, client_id, msg_data):
        """Start Fiat-Shamir authentication process"""
        session = self.client_sessions[client_id]
        session["auth_stage"] = 1
        session["auth_data"] = {
            "public_key": msg_data.get("public_key"),
            "n": msg_data.get("n")
        }
        
        logger.info(f"Starting Fiat-Shamir authentication for client {client_id}")
        # Waiting for client to send 'x' value

    def _handle_auth_message(self, client_id, message):
        """Handle authentication protocol messages"""
        session = self.client_sessions[client_id]
        
        if session["auth_stage"] == 1:
            # Received x from client, send challenge e
            try:
                x = int(message)
                session["auth_data"]["x"] = x
                session["auth_stage"] = 2
                
                # Generate random challenge (0 or 1 for basic Fiat-Shamir)
                e = random.randint(0, 1)
                session["auth_data"]["e"] = e
                
                # Send challenge to client
                self.send_to_client(session["socket"], str(e))
                logger.info(f"Sent challenge e={e} to client {client_id}")
            except ValueError:
                logger.error(f"Invalid x value from client {client_id}: {message}")
                session["auth_stage"] = 0
                
        elif session["auth_stage"] == 2:
            # Received y from client, verify proof
            try:
                y = int(message)
                auth_data = session["auth_data"]
                
                # Verify using Fiat-Shamir verification function
                is_verified = fiat_shamir_verify(
                    auth_data["x"], 
                    y, 
                    auth_data["public_key"], 
                    auth_data["n"], 
                    auth_data["e"]
                )
                
                # Send verification result to client
                result = "AUTH_SUCCESS" if is_verified else "AUTH_FAILED"
                self.send_to_client(session["socket"], result)
                
                # Update session state
                session["authenticated"] = is_verified
                session["auth_stage"] = 0
                
                logger.info(f"Authentication {result} for client {client_id}")
                
                # Notify any listeners
                if self.on_auth_result:
                    self.on_auth_result(client_id, is_verified)
                    
            except ValueError:
                logger.error(f"Invalid y value from client {client_id}: {message}")
                session["auth_stage"] = 0
                self.send_to_client(session["socket"], "AUTH_FAILED")
    
    def stop(self):
        """Stop the server and all client handlers"""
        self.running = False
        
        # Close all server sockets
        for server in self.servers[:]:
            try:
                server.close()
            except Exception as e:
                logger.error(f"Error closing server: {e}")
        
        self.servers.clear()
        self.client_handlers.clear()
        logger.info("Server stopped")
    
    def send_to_client(self, client_socket, message):
        """Send message to a specific client"""
        try:
            client_socket.send(message.encode('utf-8'))
            return True
        except Exception as e:
            logger.error(f"Error sending message to client: {e}")
            return False
        
    def get_client_auth_status(self, client_id):
        """Get authentication status for a client"""
        if client_id in self.client_sessions:
            return self.client_sessions[client_id].get("authenticated", False)
        return False