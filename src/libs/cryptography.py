from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import ECC


class Encrypter:
    def __init__(self) -> None:
        self._private_key = None
        self._public_key = None

        self._secret_key = None

        self.generate_dh_keypair()

    def get_public_key(self) -> str:
        # Сериализация ключей в строку (формат PEM)
        return self._public_key.export_key(format='PEM')

    def generate_dh_keypair(self):
        self._private_key = ECC.generate(curve='P-256')
        self._public_key = self._private_key.public_key()

    def calculate_dh_secret(self, peer_pub_key: str):
        peer_pub_key = ECC.import_key(peer_pub_key)
        # Используем HKDF для генерации общего секретного ключа фиксированного размера
        self._secret_key = HKDF(self._private_key.exchange_ecdh(peer_pub_key), 16, b"", SHA256)

    def encrypt(self, message: bytes) -> tuple[bytes, bytes]:
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