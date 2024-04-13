from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes


import os
from typing import NamedTuple
from config import config

PEM_FormatData = str
B64_FormatData = str

class EncryptedData(NamedTuple):
    data_b64: B64_FormatData
    iv_b64: B64_FormatData

class Encrypter:
    def __init__(self, keys_path: str) -> None:
        """
            Инициализирует объект Encrypter, загружает необходимые ключи.

        Args:
            keys_path: Путь к директории с ключами.
        """
        self._keys_path: str = keys_path
        self._private_key: ECC.EccKey
        self._public_key: ECC.EccKey
        self._secret_key: bytes = b''
        self._database_key: bytes = b''
        self._rsa_private_key: str = ''

        os.makedirs(self._keys_path, exist_ok=True)
        self._load_database_encode_key()
        self._load_rsa_key()
        self.generate_dh_keypair()

    def get_public_key(self) -> PEM_FormatData:
        """
            Возвращает публичный ключ в формате PEM.

        Returns:
            Публичный ключ в формате PEM.
        """
        return self._public_key.export_key(format='PEM')

    def generate_dh_keypair(self) -> None:
        """
            Генерирует новую пару ключей ECC для обмена ключами Diffie-Hellman.
        """
        self._private_key = ECC.generate(curve='P-256')
        self._public_key = self._private_key.public_key()

    def calculate_dh_secret(self, peer_pub_key: PEM_FormatData) -> None:
        """
            Вычисляет общий секрет, используя публичный ключ другой стороны.

        Args:
            peer_pub_key: Публичный ключ другой стороны в формате PEM.
        """
        _peer_pub_key: ECC.EccKey = ECC.import_key(peer_pub_key)
        # Вычисляем общий секрет, умножая публичный ключ другой стороны на наш приватный ключ
        shared_secret_point  = self._private_key.d * _peer_pub_key.pointQ # type: ignore
        # Преобразование координаты X общего секрета в байты
        shared_secret_bytes = shared_secret_point.x.to_bytes(32, 'big')  # Для P-256 размер 32 байта
        # Использование HKDF для получения ключа фиксированного размера из общего секрета
        self._secret_key = HKDF(shared_secret_bytes, 16, b"", SHA256) # type: ignore

    def encrypt(self, message: str) -> EncryptedData:
        """
            Шифрует сообщение и возвращает зашифрованный текст и IV, оба в кодировке base64.

        Args:
            message: Сообщение для шифрования.

        Returns:
            Кортеж, содержащий зашифрованный текст и IV в base64.
        """
        cipher = AES.new(self._secret_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
        iv = cipher.iv

        # Кодирование зашифрованных данных и IV в base64 для передачи в JSON
        return EncryptedData(data_b64=b64encode(ct_bytes).decode('utf-8'), iv_b64=b64encode(iv).decode('utf-8'))

    def decrypt(self, data: EncryptedData) -> str:
        """
            Расшифровывает сообщение, закодированное в base64, и IV.

        Args:
            data: Зашифрованное сообщение в base64

        Returns:
            Расшифрованное сообщение.
        """
        iv = b64decode(data.data_b64)
        ct_bytes = b64decode(data.iv_b64)
        cipher = AES.new(self._secret_key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct_bytes), AES.block_size)
        return pt.decode()
    
    def encode_data(self, data: str) -> bytes:
        """
            Шифрует данные для хранения в базе данных.

        Args:
            data: Данные для шифрования.

        Returns:
            Зашифрованные данные, включая инициализирующий вектор (IV).
        """
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self._database_key, AES.MODE_CBC, iv)
        ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
        return iv + ct_bytes

    def decode_data(self, data: bytes) -> str:
        """
            Расшифровывает данные из базы данных.

        Args:
            data: Зашифрованные данные, включая IV.

        Returns:
            Расшифрованные данные.
        """
        iv, ct = data[:16], data[16:]
        cipher = AES.new(self._database_key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode()
    
    @staticmethod
    def create_rsa_keys(keys_path: str, current_user_id: str) -> None:
        """
            Генерирует RSA ключи для пользователя и сохраняет их на диск.

        Args:
            keys_path: Путь к директории для сохранения ключей.
            current_user_id: Идентификатор пользователя, для которого генерируются ключи.
        """
        key = RSA.generate(2048)
        private_key_path = os.path.join(keys_path, current_user_id, config.FILES.RSA_PRIV)
        public_key_path = os.path.join(keys_path, current_user_id, config.FILES.RSA_PUB)
        
        os.makedirs(os.path.join(keys_path, current_user_id), exist_ok=True)
        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            return

        with open(private_key_path, "w") as prv_file, open(public_key_path, "w") as pub_file:
            prv_file.write(key.export_key().decode())
            pub_file.write(key.publickey().export_key().decode())

    def sign_message(self, encrypted_message: B64_FormatData) -> B64_FormatData:
        """
            Подписывает сообщение с использованием закрытого RSA ключа.

        Args:
            encrypted_message: Зашифрованное сообщение для подписи.

        Returns:
            Подпись, закодированная в base64.
        """
        key = RSA.import_key(self._rsa_private_key.encode())
        h = SHA256.new(b64decode(encrypted_message))
        signature = pkcs1_15.new(key).sign(h)
        return b64encode(signature).decode('utf-8')

    def verify_signature(self, public_key: str, encrypted_message: B64_FormatData, signature: B64_FormatData) -> bool:
        """
            Проверяет подпись сообщения, используя публичный RSA ключ отправителя.

        Args:
            public_key: Публичный ключ отправителя.
            encrypted_message: Зашифрованное сообщение.
            signature: Подпись для проверки.

        Returns:
            True, если подпись верифицирована, иначе False.
        """
        key = RSA.import_key(public_key.encode())
        h = SHA256.new(b64decode(encrypted_message))
        try:
            pkcs1_15.new(key).verify(h, b64decode(signature))
            return True
        except (ValueError, TypeError):
            return False

    def _create_database_encode_key(self) -> None:
        """
            Создает новый ключ шифрования для базы данных.
        """
        key = get_random_bytes(32)
        self._save_database_encode_key(key)

    def _load_database_encode_key(self) -> None:
        """
            Загружает ключ шифрования базы данных из файла, создавая его при необходимости.
        """
        db_key = os.path.join(self._keys_path, config.FILES.DB_KEY)
        if os.path.exists(db_key):
            with open(db_key, 'rb') as key_file:
                self._database_key = key_file.read()
                return
        self._create_database_encode_key()

    def _save_database_encode_key(self, key: bytes) -> None:
        """
            Сохраняет ключ шифрования базы данных в файл.
        """
        with open(os.path.join(self._keys_path, config.FILES.DB_KEY), 'wb') as key_file:
            key_file.write(key)
    
    def _load_rsa_key(self) -> None:
        """
            Загружает закрытый RSA ключ из файла.
        """
        rsa_key = os.path.join(self._keys_path, config.FILES.RSA_PRIV)
        if os.path.exists(rsa_key):
            with open(rsa_key, 'r') as key_file:
                self._rsa_private_key = key_file.read()
                return
        raise FileNotFoundError