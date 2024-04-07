from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes

import os

class Encrypter:
    def __init__(self, database_key_path) -> None:
        self._private_key = None
        self._public_key = None
        self._secret_key = None

        self._database_key_path = database_key_path
        self._database_key = None

        self._load_database_encode_key()
        self.generate_dh_keypair()

    def get_public_key(self) -> str:
        # Сериализация ключей в строку (формат PEM)
        return self._public_key.export_key(format='PEM')

    def generate_dh_keypair(self):
        """Генерирует пару ключей ECC."""

        self._private_key = ECC.generate(curve='P-256')
        self._public_key = self._private_key.public_key()

    def calculate_dh_secret(self, peer_pub_key: str):
        """Вычисляет общий секрет с использованием ECDH."""

        peer_pub_key = ECC.import_key(peer_pub_key)
       
        # Вычисляем общий секрет, умножая публичный ключ другой стороны на наш приватный ключ
        shared_secret_point  = self._private_key.d * peer_pub_key.pointQ
        # Преобразование координаты X общего секрета в байты
        shared_secret_bytes = shared_secret_point.x.to_bytes(32, 'big')  # Для P-256 размер 32 байта
        # Использование HKDF для получения ключа фиксированного размера из общего секрета
        self._secret_key = HKDF(shared_secret_bytes, 16, b"", SHA256)

    def encrypt(self, message: str) -> tuple[bytes, bytes]:
        # Шифрование данных
        cipher = AES.new(self._secret_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
        iv = cipher.iv

        # Кодирование зашифрованных данных и IV в base64 для передачи в JSON
        ct_b64 = b64encode(ct_bytes).decode('utf-8')
        iv_b64 = b64encode(iv).decode('utf-8')

        return ct_b64, iv_b64

    def decrypt(self, message_b64: bytes, iv_b64: bytes) -> str:
        iv = b64decode(iv_b64)
        ct_bytes = b64decode(message_b64)

        # Дешифрование данных
        cipher = AES.new(self._secret_key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct_bytes), AES.block_size)

        return pt.decode()
    
    def _create_database_encode_key(self) -> None:
        if self._database_key is None:
            self._database_key = get_random_bytes(32)
            self._save_database_encode_key()

    def _load_database_encode_key(self) -> None:
        if os.path.exists(self._database_key_path):
            with open(self._database_key_path, 'rb') as key_file:
                self._database_key = key_file.read()
                return
        self._create_database_encode_key()

    def _save_database_encode_key(self) -> None:
        with open(self._database_key_path, 'wb') as key_file:
            key_file.write(self._database_key)

    def encode_data(self, data: str) -> bytes:
        # Генерируем инициализирующий вектор
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self._database_key, AES.MODE_CBC, iv)
        # Шифруем и добавляем padding к данным
        ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
        return iv + ct_bytes
    
    def decode_data(self, data: bytes) -> str:
        # Инициализирующий вектор - первые 16 байт
        iv = data[:16]
        ct = data[16:]
        cipher = AES.new(self._database_key, AES.MODE_CBC, iv)
        # Убираем padding после дешифрования
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode()