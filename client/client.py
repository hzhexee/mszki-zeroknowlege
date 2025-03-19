import socket
import time
import json
import logging
import random
from typing import Optional, Dict, Any
from fiat_shamir.authentication import fiat_shamir_authenticate

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('ZKP-Client')

# Global socket reference
client_socket = None
server_host = 'localhost'
server_port = 8000

def connect_to_server(host='localhost', port=8000):
    """Connect to the ZKP server"""
    global client_socket, server_host, server_port
    server_host = host
    server_port = port
    
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((host, port))
        logger.info(f"Connected to server at {host}:{port}")
        return True
    except Exception as e:
        logger.error(f"Failed to connect to server: {e}")
        return False

def send_to_server(message):
    """Send message to the server"""
    global client_socket
    
    if not client_socket:
        logger.error("Not connected to server")
        return False
    
    try:
        if isinstance(message, (int, float)):
            message = str(message)
        
        client_socket.send(message.encode('utf-8'))
        logger.info(f"Sent to server: {message}")
        return True
    except Exception as e:
        logger.error(f"Error sending message: {e}")
        return False

def receive_from_server(timeout=30):
    """Receive message from the server"""
    global client_socket
    
    if not client_socket:
        logger.error("Not connected to server")
        return None
    
    try:
        client_socket.settimeout(timeout)
        data = client_socket.recv(1024)
        if data:
            message = data.decode('utf-8')
            logger.info(f"Received from server: {message}")
            return message
        else:
            logger.warning("No data received from server")
            return None
    except socket.timeout:
        logger.error("Timeout waiting for server response")
        return None
    except Exception as e:
        logger.error(f"Error receiving message: {e}")
        return None

def disconnect_from_server():
    """Disconnect from the server"""
    global client_socket
    
    if client_socket:
        try:
            client_socket.close()
            logger.info("Disconnected from server")
        except Exception as e:
            logger.error(f"Error disconnecting: {e}")
        finally:
            client_socket = None

def start_authentication(protocol='fiat-shamir', **kwargs):
    """Start authentication process with the server"""
    if not client_socket:
        logger.error("Not connected to server")
        return False
    
    if protocol.lower() == 'fiat-shamir':
        private_key = kwargs.get('private_key')
        n = kwargs.get('n')
        
        if not private_key or not n:
            logger.error("Missing required parameters for Fiat-Shamir protocol")
            return False
            
        # Отправляем запрос на аутентификацию
        auth_request = {
            "action": "auth_request",
            "protocol": "fiat-shamir",
            "public_key": pow(private_key, 2, n),  # v = s^2 mod n
            "n": n
        }
        
        send_to_server(json.dumps(auth_request))
        
        # Выполняем протокол
        result = fiat_shamir_authenticate(private_key, n)
        return result
    
    else:
        logger.error(f"Unsupported protocol: {protocol}")
        return False
