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