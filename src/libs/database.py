import json
from logging import Logger
import os
import sqlite3
from typing import Dict, List, Tuple

from config import UserIdHashType, UserIdType, config
from libs.cryptography import Encrypter
from libs.message import MessageIdType, MessageTextData
from libs.structs import ClientInfo, DHTNodeHistory
from libs.utils import strip_bad_symbols

class HistoryDatabaseManager:
    DB_PATH = config.FILES.HISTORY

    def __init__(self, user_id_hash: str, user_password: str, logger: Logger) -> None:
        self._user_id_hash: str = user_id_hash
        self._user_password: str = user_password
        self._logger: Logger = logger
        self._database_key: bytes = b''
        
        self._table_name = ''

    def set_table_name(self, user_id_hash: str, peer_id_hash: str):
        """
            Создает шаблоны названий для таблицы базы данных для данного диалога.

        Args:
            user_id_hash (str): Наш id
            peer_id_hash (str): Id собеседника
        """
        self._peer_id_hash = peer_id_hash
        self._table_name = strip_bad_symbols(f'table_{user_id_hash}_{peer_id_hash}')
        self._database_key = Encrypter.load_database_encode_key(self._user_id_hash, self._user_password, self._peer_id_hash)


    def connect(self):
        """ Устанавливает соединение с базой данных и возвращает объект соединения. """
        return sqlite3.connect(HistoryDatabaseManager.DB_PATH)

    def save_data(self, messages: List[MessageTextData], is_outbound_message_buffer: bool = False) -> None:
        """
        Сохраняет данные в указанную таблицу базы данных.

        Args:
            table (List[MessageTextData]): Список сообщений.
            is_outbound_message_buffer (bool): Флаг того, что сохраняются данные их временного буфера.
        """
        if not messages:
            return
        
        _messages = [(not is_outbound_message_buffer, Encrypter.encrypt_with_aes(self._database_key, msg.model_dump_json())) for msg in messages]


        try:
            self._logger.debug(f"Добавляю [{len(_messages)}] сообщение(-ий) в базу данных для клиента [{self._peer_id_hash}].")
            conn = self.connect()
            cursor = conn.cursor()
             # SQL-запрос для вставки данных
            query = f"INSERT INTO {self._table_name} (sync_state, data) VALUES (?, ?)"
            
            # Вставляем множество записей
            cursor.executemany(query, _messages)

             # Сохраняем изменения
            conn.commit()
            self._logger.debug(f"[{len(_messages)}] сообщение(-ий) успешно добавлено(-ы) в базу данных для клиента [{self._peer_id_hash}].")
        except sqlite3.Error as e:
            self._logger.error(f'Ошибка при добавлении данных в БД для клиента [{self._peer_id_hash}]. Ошибка [{e}].')
        finally:
            if conn: # type: ignore
                conn.close()  

    def load_data(self) -> Tuple[List[MessageTextData], Dict[MessageIdType, MessageTextData]]:
        """
        Загружает данные из указанной таблицы с учетом условий.

        Returns:
            Tuple[List[MessageTextData], Dict[MessageIdType, MessageTextData]]:
            Кортеж из списка синхронизированных и словаря несинхронизированных сообщений.
        """
        self._logger.debug(f'Подключаюсь к базе данных и загружаю историю диалога с клиентом [{self._peer_id_hash}].')

        sent_messages: List[MessageTextData] = []
        unsent_messages: Dict[MessageIdType, MessageTextData] = {}
        try:    
            # Подключение к базе данных (или её создание, если она не существует)
            conn = self.connect()
            cursor = conn.cursor()

            # Создание таблицы диалога
            cursor.execute(f'CREATE TABLE IF NOT EXISTS {self._table_name} (sync_state INTEGER, data BLOB)')

            # Выполнение запроса на выборку всех записей из таблицы
            req = f"SELECT * FROM {self._table_name}"
            cursor.execute(req)
            
            # Получение всех результатов
            all_rows = cursor.fetchall()
            
            for row in all_rows:
                decoded_row = MessageTextData.parse_raw((Encrypter.decrypt_with_aes(self._database_key, row[1])))
                sent_messages.append(decoded_row) if int(row[0]) else unsent_messages.update({decoded_row.id: decoded_row})

            if sent_messages:
                sent_messages.sort(key=lambda x: x.id)

            self._logger.debug(f'Было загружено [{len(sent_messages)}] сообщения(-ий) для клиента [{self._peer_id_hash}] из истории.')
            self._logger.debug(f'Было загружено [{len(unsent_messages)}] сообщения(-ий) для клиента [{self._peer_id_hash}], требующих повторной отправки.')

            req = f"DELETE FROM {self._table_name} WHERE sync_state = ?"
            cursor.execute(req, (False,))

            # Сохранение изменений и закрытие соединения с базой данных
            conn.commit()


        except sqlite3.Error as e:
            self._logger.error(f'Не удалось подключиться к базе данных по пути [{HistoryDatabaseManager.DB_PATH}]. Ошибка [{e}].')
        finally:
            if conn: # type: ignore
                conn.close()
        return sent_messages, unsent_messages

class KeyLoadingError(FileNotFoundError):
    """Исключение возникает, когда загрузка ключа из файла не удаётся."""

    def __init__(self, message: str = "Не удалось загрузить ключ"):
        """
        Инициализирует исключение с сообщением об ошибке.

        Args:
            message (str): Сообщение об ошибке с дополнительной информацией.
        """
        super().__init__(f"{message}")

class DatabaseCreationError(Exception):
    """Исключение, возникающее при ошибке создания базы данных."""

    def __init__(self, message="Не удалось создать базу данных", *args):
        super().__init__(message, *args)

class DatabaseGetDataError(Exception):
    """Исключение, возникающее при ошибке получения данных из базы данных."""

    def __init__(self, message="Не удалось получить данные", *args):
        super().__init__(message, *args)

class DatabaseSetDataError(Exception):
    """Исключение, возникающее при ошибке запиши данных в базу данных."""

    def __init__(self, message="Не удалось записать данные", *args):
        super().__init__(message, *args)


class AccountDatabaseManager:
    DB_PATH = config.FILES.ACCOUNTS

    @staticmethod
    def connect():
        """ Устанавливает соединение с базой данных и возвращает объект соединения. """
        return sqlite3.connect(AccountDatabaseManager.DB_PATH)
    
    @staticmethod
    def create_database() -> None:
        """
            Создание базы данных.
        
        Raises:
            DatabaseCreationError: Если не удалось создать таблицы в базе данных.
        """
        try:
            conn = AccountDatabaseManager.connect()
            cursor = conn.cursor()
            
            # Создание таблицы информации о пользователе
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_info (
                user_id TEXT PRIMARY KEY,
                password_hash TEXT,
                user_name BLOB,
                dht_key BLOB,
                dht_node_ip BLOB,
                dht_node_port INTEGER,
                dht_client_port INTEGER,
                application_port INTEGER,
                use_local_ip INTEGER,
                dht_peers_keys BLOB
            )
            """)

            # Создание таблицы ключей шифрования
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_keys (
                user_id_hash TEXT,
                peer_id_hash TEXT,
                encryption_key BLOB,
                known_rsa_pub_keys BLOB,
                PRIMARY KEY (user_id_hash, peer_id_hash)
            )
            """)
        
            conn.commit()  # Сохранение изменений

        except sqlite3.Error as e:
            raise DatabaseCreationError(f"Не удалось создать базу данных [{AccountDatabaseManager.DB_PATH}]! Произошла ошибка [{e}].")
        finally:
            if conn: # type: ignore
                conn.close()  # Закрытие соединения с базой данных

    @staticmethod
    def get_all_registered_users() -> list[UserIdType]:
        """
            Возвращает список всех user_id из таблицы user_info.
        
        Returns:
            list[UserIdType]: Список ID зарегистрированных пользователей.
            
        Raises:
            DatabaseGetDataError: Если не удалось получить данные.
        """
        
        try:
            conn = AccountDatabaseManager.connect()
            cursor = conn.cursor()

            # Выполнение запроса на выборку всех user_id
            cursor.execute("SELECT user_id FROM user_info")
            user_ids = cursor.fetchall()  # извлекает все строки результата

            if not user_ids:
                raise DatabaseGetDataError(f'В базе данных нет зарегистрированных пользователей!')

            # Преобразование списка кортежей в список строк
            return [user_id[0] for user_id in user_ids]
        except sqlite3.Error as e:
            raise DatabaseGetDataError(f'Не удалось получить ID пользователей из таблицы [user_info]! Произошла ошибка [{e}].')
        finally:
            if conn: # type: ignore
                conn.close()

    @staticmethod
    def save_user_info(user_info: ClientInfo) -> None:
        """
            Сохраняет данные о настройках пользователя в базу данных.

        Args:
            user_info (ClientInfo): Информация о пользователе.
        
        Raises:
            DatabaseSetDataError: Если не удалось записать данные.
        """
        try:
            conn = AccountDatabaseManager.connect()
            cursor = conn.cursor()

            # Сохранение основной информации о пользователе
            req = """
            INSERT INTO user_info (user_id, password_hash, user_name, dht_key, dht_node_ip, dht_node_port, dht_client_port,
            application_port, use_local_ip, dht_peers_keys)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """

            cursor.execute(req, (
                user_info.user_id,
                user_info.user_password_hash,
                Encrypter.encrypt_with_aes(user_info.user_password.encode(), user_info.user_name),
                Encrypter.encrypt_with_aes(user_info.user_password.encode(), user_info.user_dht_key),
                Encrypter.encrypt_with_aes(user_info.user_password.encode(), user_info.dht_node_ip),
                user_info.dht_node_port,
                user_info.dht_client_port,
                user_info.application_port,
                user_info.use_local_ip,
                Encrypter.encrypt_with_aes(user_info.user_password.encode(), user_info.dht_peers_keys.model_dump_json())
            ))

            conn.commit()
        except sqlite3.Error as e:
            raise DatabaseSetDataError(f'Не удалось записать информацию о пользователе [{user_info.user_id}]! Произошла ошибка [{e}].')
        finally:
            if conn: # type: ignore
                conn.close()

    @staticmethod
    def load_password_hash(user_id: UserIdType) -> str:
        """
            Загружает хэш пароля из базы данных.

        Args:
            user_id (UserIdType): ID пользователе для загрузки.

        Raises:
            DatabaseGetDataError: Если не удалось загрузить данные или пользователь не найден.
        """
        # Выполнение запроса для получения информации о пользователе
        try:
            conn = AccountDatabaseManager.connect()
            cursor = conn.cursor()

            req = """SELECT password_hash FROM user_info WHERE user_id=?"""
            cursor.execute(req, (user_id,))
            password_hash = cursor.fetchone()

            if password_hash:
                return password_hash[0]
            raise DatabaseGetDataError(f'Пользователь с ID [{user_id}] не найден в базе данных.')
        except sqlite3.Error as e:
            raise DatabaseGetDataError(f'Произошла ошибка при получении данных пользователя [{user_id}]: [{e}].')
        finally:
            if conn: # type: ignore
                conn.close()

    @staticmethod
    def load_user_info(user_info: ClientInfo) -> None:
        """
            Загружает данные пользователя из базы данных и записывает их в переданный объект ClientInfo.

        Args:
            user_info (ClientInfo): Информация о пользователе для загрузки.

        Raises:
            DatabaseGetDataError: Если не удалось загрузить данные или пользователь не найден.
        """
        try:
            conn = AccountDatabaseManager.connect()
            cursor = conn.cursor()

            # Выполнение запроса для получения информации о пользователе
            req = """
            SELECT password_hash, user_name, dht_key, dht_node_ip, dht_node_port,
            dht_client_port, application_port, use_local_ip, dht_peers_keys
            FROM user_info
            WHERE user_id = ?
            """
            cursor.execute(req, (user_info.user_id,))
            row = cursor.fetchone()

            
            if row:
                user_info.user_password_hash = row[0]
                user_info.user_name          = Encrypter.decrypt_with_aes(user_info.user_password.encode(), row[1])
                user_info.user_dht_key       = Encrypter.decrypt_with_aes(user_info.user_password.encode(), row[2])
                user_info.dht_node_ip        = Encrypter.decrypt_with_aes(user_info.user_password.encode(), row[3])
                user_info.dht_node_port      = row[4]
                user_info.dht_client_port    = row[5]
                user_info.application_port   = row[6]
                user_info.use_local_ip       = row[7]
                user_info.dht_peers_keys=DHTNodeHistory.parse_raw(Encrypter.decrypt_with_aes(user_info.user_password.encode(), row[8]))
                
            else:
                raise DatabaseGetDataError(f'Пользователь с ID [{user_info.user_id}] не найден в базе данных.')

        except sqlite3.Error as e:
            raise DatabaseGetDataError(f'Произошла ошибка при получении данных пользователя [{user_info.user_id}]: [{e}].')
        finally:
            if conn: # type: ignore
                conn.close()

    @staticmethod
    def update_dht_peers_keys(user_id: UserIdType, dht_peers_keys: bytes) -> None:
        """
            Обновляет список известных публичных rsa ключей для PeerId. 

        Args:
            user_id (UserIdHashType): Id пользователя.
            dht_peers_keys (str): Новый список введенных пользователем DHT ключей собеседников.
            
        Raises:
            DatabaseSetDataError: Если не удалось обновить данные.
        """
        try:    
            # Подключение к базе данных (или её создание, если она не существует)
            conn = AccountDatabaseManager.connect()
            cursor = conn.cursor()

            # Параметризованный запрос для извлечения rsa ключей
            req = "UPDATE user_info SET dht_peers_keys=? WHERE user_id=?;"
            cursor.execute(req, (dht_peers_keys, user_id))            
            conn.commit()

        except sqlite3.Error as e:
            raise DatabaseSetDataError(f'Не удалось обновить список введенных пользователем DHT ключей собеседников для [{user_id}]. Произошла ошибка [{e}].')
        finally:
            if conn: # type: ignore
                conn.close()

    @staticmethod
    def save_user_keys(user_id_hash: UserIdHashType, peer_id_hash: UserIdHashType,
                       encryption_key: bytes, known_rsa_pub_keys: bytes) -> None:
        """
            Сохраняет ключ шифрования диалога и известные публичные rsa ключи для peer id. 

        Args:
            user_id_hash (UserIdHashType): Id пользователя.
            peer_id_hash (UserIdHashType): Id собеседника.

            encryption_key (bytes) Ключ шифрования диалога (зашифрованный паролем user_id).
            known_rsa_pub_keys (bytes) Сериализованный список известных публичных rsa ключей (зашифрованный паролем user_id).
        
        Raises:
            DatabaseSetDataError: Если не удалось записать данные.
        """

        try:
            conn = AccountDatabaseManager.connect()
            cursor = conn.cursor()

            req = """
            INSERT INTO user_keys (user_id_hash, peer_id_hash, encryption_key, known_rsa_pub_keys)
            VALUES (?, ?, ?, ?)
            """

            cursor.execute(req, (user_id_hash, peer_id_hash, encryption_key, known_rsa_pub_keys))

            conn.commit()
        except sqlite3.Error as e:
            raise DatabaseSetDataError(f'Не удалось записать ключи пользователей [{user_id_hash}] и [{peer_id_hash}]! Произошла ошибка [{e}].')
        finally:
            if conn: # type: ignore
                conn.close()

    @staticmethod
    def add_encryption_key_only(user_id_hash: UserIdHashType, peer_id_hash: UserIdHashType, encryption_key: bytes) -> None:
        """
            Метод для добавления записи только с ключом шифрования диалога.

        Args:
            user_id_hash (UserIdHashType): Id пользователя.
            peer_id_hash (UserIdHashType): Id собеседника.

            encryption_key (bytes) Ключ шифрования диалога (зашифрованный паролем user_id).
            
        Raises:
            DatabaseSetDataError: Если не удалось записать данные.
        """

        try:
            conn = AccountDatabaseManager.connect()
            cursor = conn.cursor()

            req = """
            INSERT INTO user_keys (user_id_hash, peer_id_hash, encryption_key)
            VALUES (?, ?, ?)
            """

            cursor.execute(req, (user_id_hash, peer_id_hash, encryption_key))

            conn.commit()
        except sqlite3.Error as e:
            raise DatabaseSetDataError(f'Не удалось записать ключ шифрования диалога пользователей [{user_id_hash}] и [{peer_id_hash}]! Произошла ошибка [{e}].')
        finally:
            if conn: # type: ignore
                conn.close()

    @staticmethod
    def add_known_rsa_pub_keys(user_id_hash: UserIdHashType, peer_id_hash: UserIdHashType, known_rsa_pub_keys: bytes) -> None:
        """
            Метод для добавления записи только с знакомыми публичными rsa ключами. 

        Args:
            user_id_hash (UserIdHashType): Id пользователя.
            peer_id_hash (UserIdHashType): Id собеседника.

            known_rsa_pub_keys (bytes) Сериализованный список известных публичных rsa ключей (зашифрованный паролем user_id).
            
        Raises:
            DatabaseSetDataError: Если не удалось записать данные.
        """

        try:
            conn = AccountDatabaseManager.connect()
            cursor = conn.cursor()

            req = """
            INSERT INTO user_keys (user_id_hash, peer_id_hash, known_rsa_pub_keys)
            VALUES (?, ?, ?)
            """

            cursor.execute(req, (user_id_hash, peer_id_hash, known_rsa_pub_keys))

            conn.commit()
        except sqlite3.Error as e:
            raise DatabaseSetDataError(f'Не удалось записать известные публичные rsa ключи пользователей [{user_id_hash}] и [{peer_id_hash}]! Произошла ошибка [{e}].')
        finally:
            if conn: # type: ignore
                conn.close()

    @staticmethod
    def fetch_encryption_key(user_id_hash: UserIdHashType, peer_id_hash: UserIdHashType) -> bytes:
        """
            Возвращает ключ шифрования истории диалога с Peer ID.

        Args:
            user_id_hash (UserIdHashType): Id пользователя.
            peer_id_hash (UserIdHashType): Id собеседника.
            
        Returns:
            bytes: Полученный ключ (зашифрованный паролем user_id).

        Raises:
            KeyLoadingError: Если не удалось найти ключ для данного Peer ID.
        """
        try:    
            # Подключение к базе данных (или её создание, если она не существует)
            conn = AccountDatabaseManager.connect()
            cursor = conn.cursor()

            # Параметризованный запрос для извлечения ключа шифрования
            req = "SELECT encryption_key FROM user_keys WHERE user_id_hash=? AND peer_id_hash=?;"
            cursor.execute(req, (user_id_hash, peer_id_hash))
            key = cursor.fetchone()
            if key:
                return key[0] # Возвращаем ключ шифрования, если он найден
            raise KeyLoadingError(f'Ключ для [{peer_id_hash}] не найден!')
        except sqlite3.Error as e:
            raise KeyLoadingError(f'Не удалось загрузить ключ для [{peer_id_hash}]. Произошла ошибка [{e}].')
        finally:
            if conn: # type: ignore
                conn.close()
    
    @staticmethod
    def fetch_known_rsa_pub_keys(user_id_hash: UserIdHashType, peer_id_hash: UserIdHashType) -> bytes:
        """
            Возвращает известные публичные rsa ключ собеседника с текущим Peer ID.

        Args:
            user_id_hash (UserIdHashType): Id пользователя.
            peer_id_hash (UserIdHashType): Id собеседника.
            
        Returns:
            bytes: Сериализованный список известных публичных rsa ключей (зашифрованный паролем user_id).

        Raises:
            KeyLoadingError: Если не удалось найти ключи для данного Peer ID.
        """
        try:    
            # Подключение к базе данных (или её создание, если она не существует)
            conn = AccountDatabaseManager.connect()
            cursor = conn.cursor()

            # Параметризованный запрос для извлечения rsa ключей
            req = "SELECT known_rsa_pub_keys FROM user_keys WHERE user_id_hash=? AND peer_id_hash=?;"
            cursor.execute(req, (user_id_hash, peer_id_hash))
            key = cursor.fetchone()
            if key:
                return key[0] # Возвращаем ключ шифрования, если он найден
            raise KeyLoadingError(f'Известные rsa ключи для [{peer_id_hash}] у [{user_id_hash}] не найдены!')
        except sqlite3.Error as e:
            raise KeyLoadingError(f'Не удалось загрузить известные rsa ключи для [{peer_id_hash}]. Произошла ошибка [{e}].')
        finally:
            if conn: # type: ignore
                conn.close()

    @staticmethod
    def get_all_keys_for_user_id(user_id_hash: UserIdHashType) -> list[tuple[bytes, bytes]]:
        """
            Возвращает список кортежей из ключа шифрования диалога (зашифрованный паролем user_id) и 
            сериализованного списока известных публичных rsa ключей (зашифрованный паролем user_id).

        Args:
            user_id_hash (UserIdHashType): Id пользователя.
            
        Returns:
            list[tuple[bytes, bytes]]: list[tuple(encryption_key, known_rsa_pub_keys)]

        Raises:
            KeyLoadingError: Если не удалось найти ключи для данного User ID.
        """
        try:    
            # Подключение к базе данных (или её создание, если она не существует)
            conn = AccountDatabaseManager.connect()
            cursor = conn.cursor()

            # Параметризованный запрос для извлечения rsa ключей
            cursor.execute("""
                SELECT encryption_key, known_rsa_pub_keys
                FROM user_keys
                WHERE user_id_hash = ?
            """, (user_id_hash,))
            keys = cursor.fetchall()

            if keys:
                return keys # Возвращаем ключ шифрования, если он найден
            raise KeyLoadingError(f'Пользователь с ID [{user_id_hash}] не найден в базе данных.')
        except sqlite3.Error as e:
            raise KeyLoadingError(f'Не удалось загрузить ключи для [{user_id_hash}]. Произошла ошибка [{e}].')
        finally:
            if conn: # type: ignore
                conn.close()

    @staticmethod
    def update_encryption_key(user_id_hash: UserIdHashType, peer_id_hash: UserIdHashType, encryption_key: bytes) -> None:
        """
            Обновляет список известных публичных rsa ключей для PeerId. 

        Args:
            user_id_hash (UserIdHashType): Id пользователя.
            peer_id_hash (UserIdHashType): Id собеседника.
            encryption_key (bytes): Ключ шифрования диалога (зашифрованный паролем user_id).
            
        Raises:
            DatabaseSetDataError: Если не удалось обновить данные.
        """
        try:    
            # Подключение к базе данных (или её создание, если она не существует)
            conn = AccountDatabaseManager.connect()
            cursor = conn.cursor()

            # Параметризованный запрос для извлечения rsa ключей
            req = "UPDATE user_keys SET encryption_key=? WHERE user_id_hash=? AND peer_id_hash=?;"
            cursor.execute(req, (encryption_key, user_id_hash, peer_id_hash))            
            conn.commit()

        except sqlite3.Error as e:
            raise DatabaseSetDataError(f'Не удалось обновить ключ шифрования диалога для [{peer_id_hash}]. Произошла ошибка [{e}].')
        finally:
            if conn: # type: ignore
                conn.close()

    @staticmethod
    def update_known_rsa_pub_keys(user_id_hash: UserIdHashType, peer_id_hash: UserIdHashType, known_rsa_pub_keys: bytes) -> None:
        """
            Обновляет список известных публичных rsa ключей для PeerId. 

        Args:
            user_id_hash (UserIdHashType): Id пользователя.
            peer_id_hash (UserIdHashType): Id собеседника.
            known_rsa_pub_keys (bytes): Новый список публичных rsa ключей, сериализованный и зашифрованный. 
            
        Raises:
            DatabaseSetDataError: Если не удалось обновить данные.
        """
        try:    
            # Подключение к базе данных (или её создание, если она не существует)
            conn = AccountDatabaseManager.connect()
            cursor = conn.cursor()

            # Параметризованный запрос для извлечения rsa ключей
            req = "UPDATE user_keys SET known_rsa_pub_keys=? WHERE user_id_hash=? AND peer_id_hash=?;"
            cursor.execute(req, (known_rsa_pub_keys, user_id_hash, peer_id_hash))            
            conn.commit()

        except sqlite3.Error as e:
            raise DatabaseSetDataError(f'Не удалось обновить известные rsa ключи для [{peer_id_hash}]. Произошла ошибка [{e}].')
        finally:
            if conn: # type: ignore
                conn.close()