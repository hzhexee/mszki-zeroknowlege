from random import randint
import logging
import json
import sys
import os

# Добавляем корневую директорию проекта в sys.path чтобы импортировать client
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from client.client import send_to_server, receive_from_server

logger = logging.getLogger('Fiat-Shamir')

# Клиент: Генерация доказательства
def fiat_shamir_authenticate(private_key, n):
    """
    Выполняет протокол аутентификации Фиата-Шамира со стороны клиента
    
    Args:
        private_key (int): Закрытый ключ клиента s
        n (int): Модуль n
    
    Returns:
        bool: True если аутентификация успешна, иначе False
    """
    try:
        # Шаг 1: Генерируем случайное r и вычисляем x = r² mod n
        r = randint(1, n - 1)
        x = pow(r, 2, n)  # x = r² mod n
        
        # Отправляем x серверу
        send_to_server(x)
        
        # Шаг 2: Получаем случайное битовое значение e от проверяющего (сервера)
        e_str = receive_from_server()
        if not e_str:
            logger.error("Failed to receive challenge (e) from server")
            return False
            
        try:
            e = int(e_str)
        except ValueError:
            logger.error(f"Received invalid challenge: {e_str}")
            return False
        
        # Шаг 3: Вычисляем y = r * s^e mod n и отправляем серверу
        y = (r * pow(private_key, e, n)) % n
        send_to_server(y)
        
        # Шаг 4: Получаем результат от сервера
        result = receive_from_server()
        
        # Проверяем результат
        if result == "AUTH_SUCCESS":
            logger.info("Authentication successful")
            return True
        else:
            logger.warning(f"Authentication failed: {result}")
            return False
            
    except Exception as e:
        logger.exception(f"Error during Fiat-Shamir authentication: {e}")
        return False

# Сервер: Проверка доказательства
def fiat_shamir_verify(client_x, client_y, public_key, n, e):
    """
    Проверка доказательства для протокола Фиата-Шамира со стороны сервера
    
    Args:
        client_x (int): Значение x, полученное от клиента (x = r² mod n)
        client_y (int): Значение y, полученное от клиента (y = r * s^e mod n)
        public_key (int): Публичный ключ клиента v (v = s² mod n)
        n (int): Модуль n
        e (int): Случайный бит, отправленный клиенту (0 или 1)
        
    Returns:
        bool: True если проверка успешна, иначе False
    """
    # Вычисляем левую часть: y² mod n
    left = pow(client_y, 2, n)
    
    # Вычисляем правую часть: x * v^e mod n
    right = (client_x * pow(public_key, e, n)) % n
    
    # Проверяем равенство: y² ≡ x * v^e (mod n)
    return left == right

# Функция генерации ключей для протокола Фиата-Шамира
def generate_fiat_shamir_keys(n):
    """
    Генерирует пару ключей для протокола Фиата-Шамира
    
    Args:
        n (int): Модуль n
    
    Returns:
        tuple: (private_key, public_key) - пара закрытый и открытый ключи
    """
    # Выбираем случайное число s, взаимно простое с n
    while True:
        s = randint(2, n - 1)
        # В полной реализации нужно проверять, что gcd(s, n) = 1
        # Для простоты мы этот шаг пропускаем
        break
        
    # Вычисляем открытый ключ v = s² mod n
    v = pow(s, 2, n)
    
    return s, v
