from base64 import b64encode, b64decode
import binascii
import random
import string
from typing import Union
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes


import os
from pydantic import BaseModel

from config import UserIdHashType, config, PathType, UserIdType
from libs.additional_exeptions import UnavaliableDataFormatError

PEM_FormatData = str
B64_FormatData = str

RSA_KeyType = str

class EncryptedData(BaseModel):
    data_b64: B64_FormatData
    iv_b64: B64_FormatData


class Base64DecodingError(Exception):
    """Исключение возникает, когда декодирование из Base64 не удается из-за неверного формата."""

    def __init__(self, message: str = "Не удалось расшифровать данные Base64. Неверный формат данных."):
        """
        Инициализирует исключение с сообщением об ошибке.

        Args:
            message (str): Описание ошибки, по умолчанию информация о неудачном декодировании.
        """
        super().__init__(message)

class RSAKeyLoadingError(FileNotFoundError):
    """Исключение возникает, когда загрузка RSA ключей из файла не удаётся."""

    def __init__(self, rsa_key_path: PathType, message: str = "Не удалось загрузить ключи RSA из файла"):
        """
        Инициализирует исключение с путём к файлу и сообщением об ошибке.

        Args:
            rsa_key_path (PathType): Путь к файлу ключам RSA.
            message (str): Сообщение об ошибке с дополнительной информацией.
        """
        super().__init__(f"{message}: {rsa_key_path}")


class Encrypter:
    def __init__(self, keys_path: PathType, user_id_hash: UserIdType, user_password: str) -> None:
        """
            Инициализирует объект Encrypter, загружает необходимые ключи.

        Args:
            keys_path: Путь к директории с ключами.
        """
        self._keys_path: PathType = os.path.join(keys_path, user_id_hash)
        self._private_key: ECC.EccKey
        self._public_key: ECC.EccKey
        self._secret_key: bytes = b''
        self._rsa_public_key: RSA.RsaKey
        self._rsa_private_key: RSA.RsaKey

        os.makedirs(self._keys_path, exist_ok=True)
        self._load_rsa_keys(user_password)
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

    @staticmethod
    def encode_to_b64(message: Union[str, bytes]) -> B64_FormatData:
        """
            Кодирует строку или байты в строку Base64.

        Args:
            message (Union[str, bytes]): Сообщение для кодирования, может быть строкой или байтами.

        Returns:
            str: Закодированное сообщение в формате Base64.

        Raises:
            UnavaliableDataFormatError: Если формат `message` не поддерживается.
        """
        if isinstance(message, str):
            # Кодируем строку в байты, затем в Base64 и декодируем обратно в строку
            return b64encode(message.encode('utf-8')).decode('utf-8')
        elif isinstance(message, bytes):
            # Кодируем байты прямо в Base64 и декодируем обратно в строку
            return b64encode(message).decode('utf-8')
        else:
            # Если тип данных не str и не bytes, поднимаем исключение
            raise UnavaliableDataFormatError("Предоставленный формат данных не поддерживается для кодировки Base64.")

    @staticmethod
    def decode_from_b64(encoded_data: B64_FormatData) -> bytes:
        """
            Декодирует данные из строки Base64 в байты.

        Args:
            encoded_data (B64_FormatData): Строка данных, закодированных в Base64.

        Returns:
            bytes: Декодированные байты данных.

        Raises:
            Base64DecodingError: Если декодирование не удается из-за некорректного формата.
        """
        try:
            return b64decode(encoded_data)
        except (binascii.Error, ValueError) as e:
            # Обработка исключений, специфичных для ошибок декодирования Base64
            raise Base64DecodingError(f"Ошибка декодирования данных Base64: {str(e)}")

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
        return EncryptedData(data_b64=Encrypter.encode_to_b64(ct_bytes), iv_b64=Encrypter.encode_to_b64(iv))

    def decrypt(self, data: EncryptedData) -> str:
        """
            Расшифровывает сообщение, закодированное в base64, и IV.

        Args:
            data: Зашифрованное сообщение в base64

        Returns:
            Расшифрованное сообщение.
        """
        iv = self.decode_from_b64(data.iv_b64)
        ct_bytes = self.decode_from_b64(data.data_b64)
        cipher = AES.new(self._secret_key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct_bytes), AES.block_size)
        return pt.decode()
    
    @staticmethod
    def encrypt_with_aes(key: bytes, data: str) -> bytes:
        """
            Шифрует данные с использованием алгоритма AES.

        Args:
            data: Данные для шифрования.

        Returns:
            Зашифрованные данные, включая инициализирующий вектор (IV).
        """
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
        return iv + ct_bytes
    
    @staticmethod
    def decrypt_with_aes(key: bytes, data: bytes) -> str:
        """
            Расшифровывает данные с использованием алгоритма AES.

        Args:
            data: Зашифрованные данные, включая IV.

        Returns:
            Расшифрованные данные.
        """
        iv, ct = data[:16], data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode()
    
    @staticmethod
    def create_rsa_keys(keys_path: PathType, user_id_hash: UserIdHashType, user_password: str) -> None:
        """
            Генерирует RSA ключи для пользователя и сохраняет их на диск.

        Args:
            keys_path: Путь к директории для сохранения ключей.
            user_id_hash: Идентификатор пользователя, для которого генерируются ключи.
            user_password: Пароль пользователя, для шифрования ключей.
        """
        private_key_path = os.path.join(keys_path, user_id_hash, config.FILES.RSA_PRIV)
        public_key_path = os.path.join(keys_path, user_id_hash, config.FILES.RSA_PUB)
        
        os.makedirs(os.path.join(keys_path, user_id_hash), exist_ok=True)
        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            return

        key = RSA.generate(2048)
        with open(private_key_path, "wb") as prv_file, open(public_key_path, "wb") as pub_file:
            prv_file.write(Encrypter.encrypt_with_aes(user_password.encode(), key.export_key().decode()))
            pub_file.write(Encrypter.encrypt_with_aes(user_password.encode(), key.publickey().export_key().decode()))

    def encrypt_with_rsa(self, message: str, rsa_public_key: RSA_KeyType = '') -> B64_FormatData:
        """
            Шифрует данные с использованием публичного ключа RSA.

        Args:
            message (str): Сообщение для шифрования.
            rsa_public_key (RSA_KeyType): Публичный ключ RSA для шифрования. Если ничего не передавать, то шифрует нашим ключом.

        Returns:
            B64_FormatData: Шифрованные данные.
        """
        _rsa_public_key = RSA.import_key(rsa_public_key.encode()) if rsa_public_key else self._rsa_public_key
        cipher = PKCS1_OAEP.new(_rsa_public_key, hashAlgo=SHA256)
        encrypted_message = cipher.encrypt(message.encode())
        return Encrypter.encode_to_b64(encrypted_message)

    def decrypt_with_rsa(self, encrypted_message: B64_FormatData) -> str:
        """
            Расшифровывает данные с использованием приватного ключа RSA.

        Args:
            encrypted_message (B64_FormatData): Шифрованные данные.

        Returns:
            str: Расшифрованное сообщение.
        """
        cipher = PKCS1_OAEP.new(self._rsa_private_key, hashAlgo=SHA256)
        decrypted_message = cipher.decrypt(self.decode_from_b64(encrypted_message))
        return decrypted_message.decode()

    def sign_message(self, encrypted_message: B64_FormatData) -> B64_FormatData:
        """
            Подписывает сообщение с использованием закрытого RSA ключа.

        Args:
            encrypted_message: Зашифрованное сообщение для подписи.

        Returns:
            Подпись, закодированная в base64.
        """
        h = SHA256.new(self.decode_from_b64(encrypted_message))
        signature = pkcs1_15.new(self._rsa_private_key).sign(h)
        return Encrypter.encode_to_b64(signature)

    def verify_signature(self, public_key: RSA_KeyType, encrypted_message: B64_FormatData, signature: B64_FormatData) -> bool:
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
        h = SHA256.new(self.decode_from_b64(encrypted_message))
        try:
            pkcs1_15.new(key).verify(h, self.decode_from_b64(signature))
            return True
        except (ValueError, TypeError):
            return False

    def get_rsa_public_key(self) -> RSA_KeyType:
        return self._rsa_public_key.export_key(format='PEM').decode('utf-8')

    @staticmethod
    def _create_database_encode_key() -> str:
        """
            Создает новый ключ шифрования для базы данных.
        """
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))

    @staticmethod
    def load_database_encode_key(user_id_hash: UserIdHashType, user_password: str, peer_id_hash: UserIdHashType) -> bytes:
        """
            Загружает ключ шифрования базы данных, создавая его при необходимости.
        """
        from libs.database import AccountDatabaseManager, KeyLoadingError

        try:
            db_key = AccountDatabaseManager.fetch_encryption_key(user_id_hash, peer_id_hash)
            return Encrypter.decrypt_with_aes(user_password.encode(), db_key).encode()
        except KeyLoadingError:
            db_key = Encrypter._create_database_encode_key()
            AccountDatabaseManager.update_encryption_key(
                user_id_hash=user_id_hash,
                peer_id_hash=peer_id_hash,
                encryption_key=Encrypter.encrypt_with_aes(user_password.encode(), db_key)
            )
            return db_key.encode()

    def _load_rsa_keys(self, user_password: str) -> None:
        """
            Загружает RSA ключи из файла.
        
        Args:
            user_password: Пароль пользователя, для расшифровки ключей.
        """
        private_key_path = os.path.join(self._keys_path, config.FILES.RSA_PRIV)
        public_key_path = os.path.join(self._keys_path, config.FILES.RSA_PUB)
        
        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            try:
                 with open(private_key_path, "rb") as prv_file, open(public_key_path, "rb") as pub_file:
                    self._rsa_private_key = RSA.import_key(
                        Encrypter.decrypt_with_aes(user_password.encode(), prv_file.read()))
                    self._rsa_public_key = RSA.import_key(
                        Encrypter.decrypt_with_aes(user_password.encode(), pub_file.read()))
            except Exception as e:
                raise RSAKeyLoadingError(self._keys_path, f"Ошибка при чтении файлов ключей RSA: {str(e)}")
        else:
            raise RSAKeyLoadingError(self._keys_path, "Файлы ключей RSA не существуют!")
    
    @staticmethod
    def load_rsa_public_key(key_path: PathType, user_id_hash: UserIdHashType, user_password: str) -> RSA_KeyType:
        """
            Загружает публичный RSA ключ из файла.
        
        Args:
            keys_path: Путь к директории для сохранения ключей.
            user_id_hash: Идентификатор пользователя, для которого загружается ключ.
            user_password: Пароль пользователя, для расшифровки ключа.
        """
        key_path = os.path.join(key_path, user_id_hash)

        public_key_path = os.path.join(key_path, config.FILES.RSA_PUB)
        
        if os.path.exists(public_key_path):
            try:
                with open(public_key_path, "rb") as pub_file:
                    rsa_public_key = Encrypter.decrypt_with_aes(user_password.encode(), pub_file.read())
                return rsa_public_key
            except Exception as e:
                raise RSAKeyLoadingError(key_path, f"Ошибка при чтении файлов ключей RSA: {str(e)}")
        else:
            raise RSAKeyLoadingError(key_path, "Файлы ключей RSA не существуют!")