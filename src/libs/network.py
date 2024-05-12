import base64
from dataclasses import dataclass
from enum import Enum
import hashlib
import json
from logging import Logger
import os
import queue
import random
import re
import socket
import string
import threading
import time
from typing import Any, Dict, List, NamedTuple, Tuple, Union
from pydantic import BaseModel, ValidationError
import requests

from config import UserIdHashType, config, IPAddressType, PortType, FilenameType, UserIdType
from dht import DHT_Client, DHTPeerProfile
from libs.cryptography import B64_FormatData, EncryptedData, Encrypter, PEM_FormatData, RSA_KeyType
from libs.database import AccountDatabaseManager, DatabaseCreationError, DatabaseGetDataError, DatabaseSetDataError, HistoryDatabaseManager, KeyLoadingError
from libs.message import *
from libs.structs import ClientInfo, DHTNodeHistory, KnownRSAPublicKeys
from libs.widgets import ClientDecision, CustomMessageBox, CustomMessageType, DialogManager, YesNoDialog

class UnavailableSessionIdError(Exception):
    """Исключение возникает при указании недопустимого идентификатора сеанса."""
    def __init__(self, message="Введен неверный идентификатор сеанса."):
        self.message = message
        super().__init__(self.message)

class NetworkCommands(Enum):
    """ Перечисление команд сетевого протокола. """
    INIT = "0"         # Инициализация соединения
    ACK = "1"          # Подтверждение получения
    PING = "2"         # Проверка активности узла
    PONG = "3"         # Ответ на проверку активности
    SEND_DATA = "4"    # Отправка данных
    RECV_DATA = "5"    # Получение данных
    SYNC_DATA = "6"    # Синхронизация данных
    EXISTS = "7"       # Сессия уже открыта
    CONNECTING_TO_OURSELVES = "8" # Подключение к самому себе

class AdditionalData(BaseModel):
    """ Дополнительные данные, связанные с сетевым сообщением. """
    user_id_hash: UserIdHashType = ''       # Идентификатор пользователя
    user_name: str = ''                     # Имя пользователя
    ecdh_public_key: 'PEM_FormatData' = ''  # Публичный ключ участника в формате PEM, для использования в ECDH
    resend_flag: bool = False               # Флаг для повторной отправки

class NetworkData(BaseModel):
    """ Описание структуры сетевых данных для передачи. """
    command_type: NetworkCommands           # Тип команды сетевого протокола
    encrypted_data: 'EncryptedData'         # Зашифрованные данные
    signature: 'B64_FormatData'             # Подпись в формате Base64
    additional: AdditionalData              # Дополнительные данные с метаинформацией
    signature_additional: 'B64_FormatData' = '' # Подпись в формате Base64

class NetworkEventType(Enum):
    """ Определяет типы событий в сетевом взаимодействии. """
    CONNECT = 0          # Событие подключения
    DISCONNECT = 1       # Событие отключения
    CLOSE_CLIENT = 2     # Событие закрытия нашего клиента
    RECEIVE_DATA = 3     # Событие получения данных
    SEND_DATA = 4        # Событие отправки данных
    REQUEST_FILE = 5     # Событие запроса файла
    FILE_ACCEPTED = 6    # Событие подтверждения получения файла
    ALREADY_EXISTS = 7   # Событие о том, что сессия уже существует
    CONNECTING_TO_OURSELVES = 8 # Подключение к самому себе
    UNKNOWN_RSA_PUBLIC_KEY = 9 # Неизвестный публичный ключ RSA
    FAILED_CONNECT = 10        # Не удалось подключиться
    LOGOUT = 11                # Выход из аккаунта

@dataclass
class NetworkEventData:
    """ Хранит данные, связанные с сетевыми событиями. """
    user_id_hash: UserIdHashType = ''
    user_name: str = ''
    address: Tuple[IPAddressType, PortType] = ('', -1)  # IP-адрес и порт
    session_id: int = -1                                # Идентификатор сессии
    resend_flag: bool = False                           # Флаг для повторной отправки данных
    data: Union['MessageTextData', List['MessageTextData'], 'MessageFileData', 'FilenameType', None] = None
    # Свойство `data` может содержать различные типы данных, в зависимости от события.

@dataclass
class NetworkEventMessage:
    """ Описывает сетевое сообщение, содержащее тип и данные события. """
    event_type: NetworkEventType  # Тип события
    event_data: NetworkEventData  # Данные события

class NetworkEvent(threading.Event):
    """ Объект события для обработки сетевых событий с очередью сообщений. """
    def __init__(self) -> None:
        super().__init__()
        self.messages: 'queue.Queue[NetworkEventMessage]' = queue.Queue()
        # Инициализация очереди для хранения и обработки сетевых событий

class __SessionCloseEvent(threading.Event):
    """ Объект события для обработки событий закрытия сессии. """
    def __init__(self) -> None:
        super().__init__()
        self.ids: 'queue.Queue[int]' = queue.Queue()

active_users: List[str] = []
session_close_event: __SessionCloseEvent = __SessionCloseEvent()

class UserSession:
    """ Управляет сетевой сессией пользователя, включая сетевые операции, шифрование и логирование. """
    
    session_counter: int = 0  # Статический счетчик для отслеживания количества сессий 

    def __init__(self, connection_socket: socket.socket, remote_address: Tuple[IPAddressType, PortType],
                 user_id_hash: UserIdHashType, user_name: str, user_password: str, peer_rsa_public_key: RSA_KeyType,
                 logger: Logger, event: NetworkEvent) -> None:
        """
        Инициализирует новую сессию пользователя.

        Args:
            socket (socket.socket): Сокет для коммуникации.
            address (Tuple[str, int]): IP-адрес и порт пользователя.
            user_id (UserIdType): Идентификатор пользователя.
            user_name (str): Имя пользователя.
            logger (Logger): Логгер для записи событий сессии.
            event (NetworkEvent): Сетевое событие, связанное с сессией.
        """
        self._connection_socket: socket.socket = connection_socket
        self._remote_address: Tuple[IPAddressType, PortType] = remote_address
        self._user_id_hash: UserIdHashType = user_id_hash
        self._user_name: str = user_name
        self._user_password: str = user_password
        self._peer_user_id_hash: UserIdHashType = ''  # Идентификатор собеседника
        self._peer_user_name: str = ''  # Имя собеседника
        self._peer_rsa_public_key: RSA_KeyType = peer_rsa_public_key  # Публичный ключ собеседника для проверки подписи
        self._logger: Logger = logger
        self._is_active: bool = True  # Флаг активности сессии
        self._last_ping_time: float = time.time()  # Время последнего пинга
        self._event: NetworkEvent = event

        # Переменная, отвечающая за решение пользователя
        # Используется, когда необходимо установить какие-либо значения, которые пользователь выбирает в UI
        # (допустим, нужно, чтобы он ответил Да/нет)
        self._client_decision: ClientDecision = ClientDecision.NONE

        self._crypto: Encrypter = Encrypter(keys_path=config.PATHS.KEYS, user_id_hash=self._user_id_hash, user_password=user_password)
        self._database: HistoryDatabaseManager = HistoryDatabaseManager(user_id_hash=self._user_id_hash, user_password=user_password, logger=self._logger)

        self._session_id: int = UserSession.session_counter
        UserSession.session_counter += 1

        self._dialog_history: List[MessageTextData] = []  # История диалога
        self._dialog_history_ids: List[MessageIdType] = []  # Идентификаторы сообщений в истории
        self._outbound_message_buffer: Dict[MessageIdType, MessageTextData] = {}  # Буфер исходящих сообщений

        self._int_size_for_message_length: int = 4  # Размер целого числа для длины сообщения

        self._thread_client_handler = threading.Thread(target=self._handle_client, daemon=True)
        self._thread_client_handler.start()

    def get_id(self) -> int:
        return self._session_id

    def set_client_decision(self, decision: ClientDecision) -> None:
        """
            Устанавливает значение поля _client_decision в одно из нескольких состояний:
                - None - нулевое состояние
                - Yes  - состояние согласия
                - No   - состояние отказа
        
        Args:
            decision (ClientDecision): Тип состояния. 
        """
        self._client_decision = decision

    def connect(self) -> int:
        """
        Устанавливает соединение с удалённым клиентом и отправляет инициализационное сообщение.

        Returns:
            int: Идентификатор сессии при успешном соединении, -1 при ошибке.
        """
        try:
            # Логгирование попытки установления соединения
            self._logger.debug(f"Устанавливаю соединение с клиентом [{self._remote_address}].")
            
            # Установление соединения с помощью сокета
            self._connection_socket.connect(self._remote_address)

            # Кодирование начального сообщения в Base64 и его подпись
            initial_message_b64: B64_FormatData = Encrypter.encode_to_b64(self._crypto.get_rsa_public_key())
            encrypted_data: EncryptedData = EncryptedData(
                data_b64=initial_message_b64,
                iv_b64=''
            )
            encrypted_data_b64: B64_FormatData = Encrypter.encode_to_b64(encrypted_data.model_dump_json())
            message_signature_b64: B64_FormatData = self._crypto.sign_message(encrypted_data_b64)

            additional_info: AdditionalData = AdditionalData(
                user_id_hash=self._user_id_hash,
                user_name=self._user_name,
                ecdh_public_key=self._crypto.get_public_key()  # Получение публичного ключа для обмена
            )
            additional_info_b64: B64_FormatData = Encrypter.encode_to_b64(additional_info.model_dump_json())
            additional_info_signature_b64: B64_FormatData = self._crypto.sign_message(additional_info_b64)


            # Сборка данных для отправки
            data_to_send = NetworkData(
                command_type=NetworkCommands.INIT,
                encrypted_data=encrypted_data,
                signature=message_signature_b64,
                additional=additional_info,
                signature_additional=additional_info_signature_b64
            )
            self._send_network_data(data_to_send)

            return self._session_id  # Возврат идентификатора сессии при успешном соединении
        
        except (OSError, ConnectionRefusedError):
            # Логгирование ошибки при соединении/отправке данных
            self._logger.debug(f'Произошло закрытие сокета. Завершаю сессию.')
            return -1  # Возврат -1 при ошибке

    def send(self, message: MessageData, is_resended: bool = False) -> None:
        """
            Отправляет сообщение указанному клиенту.

        Args:
            message (MessageData): Сообщение для отправки.
            is_resended (bool): Флаг, указывающий, нужно ли повторно отправить сообщение.

        """
        # Сериализация данных сообщения в JSON
        message_json = message.model_dump_json()
        encrypted_message: EncryptedData = self._crypto.encrypt(message_json)
        encrypted_message_b64: B64_FormatData = Encrypter.encode_to_b64(encrypted_message.model_dump_json())
        message_signature_b64: B64_FormatData = self._crypto.sign_message(encrypted_message_b64)

        # Сборка данных для отправки
        data_to_send = NetworkData(
            command_type=NetworkCommands.SEND_DATA,
            encrypted_data=encrypted_message,
            signature=message_signature_b64,
            additional=AdditionalData(
                resend_flag=is_resended
            )
        )

        self._send_network_data(data_to_send)

        # Временное кэширование исходящих текстовых сообщений
        if message.type == MessageType.Text and hasattr(message.message, 'id'):
            self._outbound_message_buffer[message.message.id] = message.message # type: ignore
    
    def close(self, logout: bool = False, silent_mode: bool = False) -> None:
        """
        Закрывает сессию, отключая соединение и регистрируя событие отключения.

        Закрывает соединение с сокетом и сообщает об отключении с помощью сетевого события.
        Сохраняет неотправленные сообщения в базу данных и завершает поток обработки клиента.

        Args:
            silent_mode (bool): Если указан в True, не отправляем ивенты для UI.
        """
        if self._is_active:
            self._is_active = False
            self._connection_socket.close()  # Закрытие сокета соединения

            # Если есть информация о собеседнике, регистрируем событие отключения
            if self._peer_user_id_hash:
                if logout:
                    self._send_event(NetworkEventType.LOGOUT)
                else:
                    self._send_event(NetworkEventType.DISCONNECT)
                # Сохранение исходящих сообщений из временного буфера в базу данных
                self._database.save_data(list(self._outbound_message_buffer.values()), is_outbound_message_buffer=True)

                global active_users 
                del active_users[active_users.index(self._peer_user_id_hash)]
            else:
                if not silent_mode:
                    self._send_event(NetworkEventType.FAILED_CONNECT)

            # Ожидание завершения потока обработки клиента, если он был запущен
            try:
                self._thread_client_handler.join()
            except RuntimeError:
                pass  # Игнорирование ошибки, если поток уже завершен

            global session_close_event
            session_close_event.ids.put(self._session_id)
            session_close_event.set()

            # Логирование завершения сессии
            self._logger.debug(f"Сессия для клиента [{self._remote_address}][{self._peer_user_id_hash} "
                               f"| {self._peer_user_name}] завершена.")

    def _send_network_data(self, data: NetworkData) -> None:
        """
            Отправляет сериализованные данные через сокет.

        Args:
            data (NetworkData): Объект данных, который необходимо отправить.

        Описание:
            Метод сериализует объект данных в JSON, кодирует в UTF-8, определяет размер данных,
            и отправляет размер данных вместе с самими данными через сокет. Логгирует информацию о передаче.
        """
        # Сборка данных для отправки
        serialized_data: bytes = data.model_dump_json().encode('utf-8')  # Сериализация и кодирование данных в JSON

        # Подготовка размера данных для отправки
        data_length: bytes = len(serialized_data).to_bytes(self._int_size_for_message_length, byteorder='big')
        
        # Отправка размера и данных через сокет
        self._connection_socket.sendall(data_length + serialized_data)
        self._logger.debug(f"Отправил {data.command_type.name} сообщение клиенту [{self._remote_address}][{self._peer_user_id_hash} "
                           f"| {self._peer_user_name}] размером [{int.from_bytes(data_length, byteorder='big')}/{len(serialized_data)}].")


    def _handle_client(self) -> None:
        """
            Обрабатывает входящие сообщения от клиента в бесконечном цикле до закрытия соединения.
        """

        # Использование метода settimeout(ping_timeout) для сокета client_socket в контексте 
        # TCP-соединений устанавливает таймаут на блокирующие операции сокета, такие как recv() и send().
        # Это значит, что операция будет ждать данных или возможности отправки данных в течение указанного времени
        # (ping_timeout), и если за это время не произойдет никаких действий, то операция завершится с исключением socket.timeout.
    
        self._connection_socket.settimeout(config.NETWORK.PING.TIMEOUT)
        self._logger.debug(f"Устанавливаю таймаут [{config.NETWORK.PING.TIMEOUT}] для клиента [{self._remote_address}].")

        while self._is_active:
            try:
                data: str = self._receive_data()
                if not data:
                    continue
                
                received_data: NetworkData = NetworkData.parse_raw(data)

                if not self._peer_rsa_public_key:
                    self._peer_rsa_public_key = self._crypto.decode_from_b64(received_data.encrypted_data.data_b64).decode('utf-8')
                
                if not self._verify_data(received_data):
                    continue

                self._logger.debug(f"Проверка подписи для клиента [{self._remote_address}]"
                                   f"[{self._peer_user_id_hash} | {self._peer_user_name}] прошла успешно.")

                match received_data.command_type:
                    case NetworkCommands.INIT:
                        self._handle_init(received_data)
                    case NetworkCommands.ACK:
                        self._handle_ack(received_data)
                    case NetworkCommands.PING:
                        self._handle_ping()
                    case NetworkCommands.PONG:
                        self._handle_pong()
                    case NetworkCommands.SEND_DATA:
                        self._handle_send(received_data)
                    case NetworkCommands.RECV_DATA:
                        self._handle_recv(received_data)
                    case NetworkCommands.SYNC_DATA:
                        self._handle_sync(received_data)
                    case NetworkCommands.EXISTS:
                        self._handle_exist(received_data)
                    case NetworkCommands.CONNECTING_TO_OURSELVES:
                        self._handle_connecting_to_ourselves()


            except socket.timeout as e:
                self._logger.debug(f"Клиент не отвечает, закрываю соединение с [{self._remote_address}]"
                                   f"[{self._peer_user_id_hash} | {self._peer_user_name}].")
                self.close()

            except (json.decoder.JSONDecodeError, ValidationError) as e:
                self._logger.error(f'Ошибка при распознании данных. [{e}]')
                self._clear_socket_buffer()
                self._logger.debug(f"Отчищаю буфер сокета для [{self._remote_address}][{self._peer_user_id_hash} | {self._peer_user_name}].")

            except BrokenPipeError:
                self._logger.debug(f'Клиент [{self._remote_address}][{self._peer_user_id_hash} | {self._peer_user_name}] завершил общение. Завершаю сессию.')
                self.close()

            except (OSError, ConnectionRefusedError):
                self._logger.debug(f'Произошло закрытие сокета. Завершаю сессию.')
                self.close()
            
            except Exception as e:
                self._logger.error(f'Произошла непредвиденная ошибка [{e}]. Завершаю сессию.')
                self.close()

    def _clear_socket_buffer(self) -> None:
        """
            Отчищаем все данные из буфера сокета.
        """
        self._connection_socket.setblocking(False)  # Установка сокета в неблокирующий режим
        try:
            while True:
                data = self._connection_socket.recv(1024)  # Попытка прочитать данные из сокета
                if not data:
                    break  # Если данных нет, выходим из цикла
        except BlockingIOError:
            pass  # Игнорируем ошибку блокировки, потому что это означает, что буфер пуст
        finally:
            self._connection_socket.setblocking(True)  # Возвращаем сокет в блокирующий режим

    def _update_ping_time(self) -> None:
        """
            Обновляет время последнего пинга для поддержания активности сессии.
        """
        self._last_ping_time = time.time()      # Обновляем время последнего пинга

    def __recvall(self, number_of_bytes: int) -> bytearray:
        """
            Получение данных из сокета с обработкой размера сообщения.

        Raises:
            socket.timeout: Если не удалось получить данные из сокета

        Returns:
            str: Данные из сокета
        """
        data = bytearray()
        while len(data) < number_of_bytes:
            packet = self._connection_socket.recv(number_of_bytes - len(data))
            if not packet:
                raise socket.timeout("No data received!")
            data.extend(packet)
        return data

    def _receive_data(self) -> str:
        """
            Получение данных из сокета с обработкой размера сообщения.

        Raises:
            socket.timeout: Если не удалось получить данные из сокета

        Returns:
            str: Данные из сокета
        """
        raw_data_size: bytes = self.__recvall(self._int_size_for_message_length)
        
        data_size: int = int.from_bytes(raw_data_size, byteorder='big')
        data: str = self.__recvall(data_size).decode()
        
        return data
    
    def _handle_init(self, received_data: NetworkData) -> None:
        """
            Обработка сообщений INIT.

        Args:
            received_data (NetworkData): Полученные данные для Init
        """
        self._update_ping_time()
        self._logger.debug(f"Получил INIT сообщение от клиента [{self._remote_address}].")

        # Проверяем, общаемся ли мы уже с человеком с данным id
        if received_data.additional.user_id_hash in active_users:
            self._send_exist()
            self.close(silent_mode=True)
            return

        # Проверяем, общаемся ли мы сами с собой
        if received_data.additional.user_id_hash == self._user_id_hash:
            self._send_connecting_to_ourselves()
            self.close(silent_mode=True)
            return

        if not self._rsa_public_key_processing(received_data):
            return

        self._update_peer_info(received_data)
        self._load_and_send_dialog_history()
        self._send_connetion_event()

    def _rsa_public_key_processing(self, received_data: NetworkData) -> bool:
        """
            Обработка публичного RSA ключа собеседника.        

        Args:
            received_data (NetworkData): Полученные данные для Init

        Returns:
            bool: True - продолжаем работу, False - выходим.
        """
        ret_val = self._check_is_known_public_rsa_key(received_data.additional.user_id_hash)
        if ret_val == 1:
            return True
        elif ret_val == -1:
            self._add_new_peer_rsa_key_to_database(received_data.additional.user_id_hash, self._peer_rsa_public_key)
            return True
        
        self._logger.debug(f'Отправляю ивент на согласие пользователя на начало диалога с [{received_data.additional.user_id_hash}].')
        self._send_event(
            NetworkEventType.UNKNOWN_RSA_PUBLIC_KEY,
            user_id_hash=received_data.additional.user_id_hash,
            user_name=received_data.additional.user_name,
            session_id=self._session_id
        )

        self._wait()

        # Если клиент решил не начинать общение с незнакомым собеседником, то просто выходим
        if self._client_decision != ClientDecision.YES:
            if self._client_decision == ClientDecision.NO:
                self._logger.debug(f'Пользователя решил не начинать диалог с [{received_data.additional.user_id_hash}].')
            self.close(silent_mode=True)
            return False
        
        # Иначе сохраняем его
        self._add_new_peer_rsa_key_to_database(received_data.additional.user_id_hash, self._peer_rsa_public_key)
        return True

    def _check_is_known_public_rsa_key(self, peer_id_hash: UserIdHashType) -> int:
        """
            Проверяет, есть ли публичный ключ собеседника в нашей БД.
        
        Args:
            peer_id_hash (UserIdHashType): Id собеседника.

        Returns:
            int: Возвращаемые значения:
                    ->  1 - есть в БД
                    ->  0 - нет в БД, но для данных id есть другие ключи
                    -> -1 - нет в БД и для этих ключей нет других значений
        """
        try:
            self._logger.debug(f'Проверяю ключ собеседника [{peer_id_hash}] на наличие в базе данных.')
            known_rsa_pub_keys = KnownRSAPublicKeys.parse_raw(
                Encrypter.decrypt_with_aes(
                    self._user_password.encode(),
                    AccountDatabaseManager.fetch_known_rsa_pub_keys(self._user_id_hash, peer_id_hash)
            ))

            if self._peer_rsa_public_key in known_rsa_pub_keys.keys:
                self._logger.debug(f'Ключ собеседника присутствует в базе данных.')
                return 1
            self._logger.debug(f'Данный ключ отсутствует в базе данных для собеседника [{peer_id_hash}].')
            return 0
        except KeyLoadingError:
            self._logger.debug(f'Это первый диалог с собеседником [{peer_id_hash}].')
            return -1

    def _wait(self, seconds: int = 5):
        """
            Ожидает заданное время, пока оно не истечет, либо не измениться параматр _client_decision.

        Args:
            seconds (int, optional): Время ожидания в секундах. По умолчанию 5.
        """
        start = time.time()
        self._logger.debug(f'Ожидаю решения пользователя [{seconds}] секунд.')
        while self._is_active and self._client_decision == ClientDecision.NONE and (time.time() - start) < seconds:
            time.sleep(0.1)
        
        if self._client_decision == ClientDecision.NONE and (time.time() - start) > seconds:
            self._logger.debug(f'Ожидание завершено. Был произведен выход по таймеру.')
        else:
            self._logger.debug(f'Ожидание завершено. Пользователь изменил состояние на [{self._client_decision.name}].')

    def _add_new_peer_rsa_key_to_database(self, peer_id_hash: UserIdHashType, peer_rsa_pub_key: RSA_KeyType) -> None:
        """
            Добавляю новый публичный RSA ключ в БД.

        Args:
            peer_id_hash (UserIdHashType): Id собеседника.
            peer_rsa_pub_key (RSA_KeyType): Ключ собеседника.
        """
        try:
            known_rsa_pub_keys = KnownRSAPublicKeys.parse_raw(
                Encrypter.decrypt_with_aes(
                    self._user_password.encode(),
                    AccountDatabaseManager.fetch_known_rsa_pub_keys(self._user_id_hash, peer_id_hash)
            ))
            
            known_rsa_pub_keys.keys.add(peer_rsa_pub_key)
            new_known_rsa_pub_keys = Encrypter.encrypt_with_aes(
                self._user_password.encode(),
                known_rsa_pub_keys.model_dump_json()
            )
            self._logger.debug('Добавляю новый публичный RSA ключ в БД к уже имеющимся.')
            AccountDatabaseManager.update_known_rsa_pub_keys(self._user_id_hash, peer_id_hash, new_known_rsa_pub_keys)
        
        except Exception:
            new_known_rsa_pub_keys = Encrypter.encrypt_with_aes(
                self._user_password.encode(),
                KnownRSAPublicKeys(keys=set([peer_rsa_pub_key])).model_dump_json()
            )
            self._logger.debug('Добавляю новый публичный RSA ключ в БД.')
            AccountDatabaseManager.add_known_rsa_pub_keys(self._user_id_hash, peer_id_hash, new_known_rsa_pub_keys)

    def _update_peer_info(self, received_data: NetworkData) -> None:
        """
            Обновление информации о собеседнике и расчет общего секрета.

        Args:
            received_data (NetworkData): Полученные данные от собеседника
        """
        self._peer_user_id_hash = received_data.additional.user_id_hash
        self._peer_user_name = received_data.additional.user_name
        self._crypto.calculate_dh_secret(received_data.additional.ecdh_public_key)

        active_users.append(self._peer_user_id_hash)

        self._database.set_table_name(self._peer_user_id_hash)

    def _load_and_send_dialog_history(self) -> None:
        """
            Загрузка истории диалога и отправка подтверждения.
        """
        self._load_dialog_history()
        self._send_ack()

    def _load_dialog_history(self) -> None:
        """
            Загружает историю диалогов из базы данных.
        """
        # Предполагаем, что метод загрузки диалога из базы данных уже реализован
        self._dialog_history, self._outbound_message_buffer = self._database.load_data()
        self._pull_dialog_history_ids()

    def _pull_dialog_history_ids(self) -> None:
        """
            Заполняет список идентификаторов сообщений.
        """
        self._dialog_history_ids = []
        for msg in self._dialog_history:
            self._dialog_history_ids.append(msg.id)

    def _send_ack(self) -> None:
        """
            Отправка сообщения ACK с историей диалога.
        """
        # Сериализация данных сообщения в JSON
        message_json: str = json.dumps(self._dialog_history_ids)
        encrypted_message: EncryptedData = self._crypto.encrypt(message_json)
        encrypted_message_b64: B64_FormatData = Encrypter.encode_to_b64(encrypted_message.model_dump_json())
        message_signature_b64: B64_FormatData = self._crypto.sign_message(encrypted_message_b64)

        additional_info: AdditionalData = AdditionalData(
            user_id_hash=self._user_id_hash,
            user_name=self._user_name,
            ecdh_public_key=self._crypto.get_public_key()  # Получение публичного ключа для обмена
        )
        additional_info_b64: B64_FormatData = Encrypter.encode_to_b64(additional_info.model_dump_json())
        additional_info_signature_b64: B64_FormatData = self._crypto.sign_message(additional_info_b64)

        # Сборка данных для отправки
        data_to_send = NetworkData(
            command_type=NetworkCommands.ACK,
            encrypted_data=encrypted_message,
            signature=message_signature_b64,
            additional=additional_info,
            signature_additional=additional_info_signature_b64
        )
        self._send_network_data(data_to_send)

    def _send_event(self, event_type: NetworkEventType, dont_set_flag: bool = False, **kwargs) -> None:
        """
            Отправка ивента.
        """
        # Использование значений из kwargs, если они предоставлены, иначе использовать атрибуты класса
        user_id_hash = kwargs.pop('user_id_hash', self._peer_user_id_hash)
        user_name = kwargs.pop('user_name', self._peer_user_name)

        # Формирование и отправка сообщения
        event_message = NetworkEventMessage(
            event_type=event_type,
            event_data=NetworkEventData(
                user_id_hash=user_id_hash,
                user_name=user_name,
                address=self._remote_address,
                **kwargs
            )
        )
        self._event.messages.put(event_message)
        if not dont_set_flag:
            self._event.set()  # Установка события для обработки другими частями системы

    def _send_connetion_event(self) -> None:
        """
            Отправка ивента о подключении клиента.
        """
        self._send_event(NetworkEventType.CONNECT, session_id=self._session_id, data=self._dialog_history)

    def _recv_ack(self, received_data: NetworkData) -> None:
        """
            Обрабатывает сообщения, полученные в Ack.

        Args:
            received_data (NetworkData): Полученные данные для Ack
        """
        encrypted_data: EncryptedData = received_data.encrypted_data
        decrypted_data: List[MessageIdType] = json.loads(self._crypto.decrypt(encrypted_data))

        # Синхранизируем данные
        threading.Thread(target=self._sync_dialog_history, args=(decrypted_data, ), daemon=True).start()

    def _handle_ack(self, received_data: NetworkData) -> None:
        """
            Обработка сообщений ACK.

        Args:
            received_data (NetworkData): Полученные данные для Ack
        """
        self._update_ping_time()
        self._logger.debug(f"Получил ACK сообщение от клиента [{self._remote_address}][{self._peer_user_id_hash} | {self._peer_user_name}].")

        self._add_new_peer_rsa_key_to_database(received_data.additional.user_id_hash, self._peer_rsa_public_key)

        self._update_peer_info(received_data)
        self._load_dialog_history()
        self._send_connetion_event()

        # Запуск постоянной проверки соединения
        threading.Thread(target=self._send_ping, daemon=True).start()
        
        # Обработка полученных данных
        self._recv_ack(received_data)

    def _send_ping(self) -> None:
        """
            Генерирует Ping сообщение каждый Ping_Interval
        """
        while self._is_active:
            while self._is_active and time.time() - self._last_ping_time < config.NETWORK.PING.INTERVAL:
                time.sleep(0.1)
            try:
                self._send_ping_or_pong(NetworkCommands.PING)
                self._last_ping_time = time.time()      # Обновляем время последнего пинга
            except OSError:
                self._logger.debug(f"Не удалось отправить PING клиенту [{self._remote_address}]"
                                   f"[{self._peer_user_id_hash} | {self._peer_user_name}].")

    def _handle_ping(self) -> None:
        """
            Обработка сообщений PING.
        """
        self._update_ping_time()
        self._logger.debug(f"Получил PING сообщение от клиента [{self._remote_address}]"
                                   f"[{self._peer_user_id_hash} | {self._peer_user_name}].")
        self._send_ping_or_pong(NetworkCommands.PONG)
        
    def _send_ping_or_pong(self, message_type: NetworkCommands) -> None:
        """
            Отправляет Ping или Pong сообщение в зависимости от переданного аргумента.
        Args:
            message_type (NetworkCommands): Тип сообщения (Ping или Pong)
        """
        encrypted_message: EncryptedData = self._crypto.encrypt(message_type.name)
        encrypted_message_b64: B64_FormatData = Encrypter.encode_to_b64(encrypted_message.model_dump_json())
        message_signature_b64: B64_FormatData = self._crypto.sign_message(encrypted_message_b64)

        # Сборка данных для отправки
        data_to_send = NetworkData(
            command_type=message_type,
            encrypted_data=encrypted_message,
            signature=message_signature_b64,
            additional=AdditionalData()
        )
        self._send_network_data(data_to_send)

    def _handle_pong(self) -> None:
        """
            Обработка сообщений PONG.
        """
        self._update_ping_time()
        self._logger.debug(f"Получил PONG сообщение от клиента [{self._remote_address}]"
                                   f"[{self._peer_user_id_hash} | {self._peer_user_name}].")

    def _handle_send(self, received_data: NetworkData) -> None:
        """
            Обработка сообщений Send.

        Args:
            received_data (NetworkData): Полученные данные для Send
        """
        self._update_ping_time()
        self._logger.debug(f"Получил SEND сообщение от клиента [{self._remote_address}][{self._peer_user_id_hash} | {self._peer_user_name}].")
        
        decrypted_data: MessageData = MessageData.parse_raw(self._crypto.decrypt(received_data.encrypted_data))
        
        match decrypted_data.type:
            case MessageType.Text:
                self._handle_text_message(decrypted_data.message, received_data.additional.resend_flag) # type: ignore
            case MessageType.File:
                self._handle_file_message(decrypted_data.message) # type: ignore
    
    def _handle_text_message(self, message: MessageTextData, resend_flag: bool = False) -> None:
        """
            Обрабатывает текстовые сообщения, проверяя, является ли сообщение повторным, и если нет, сохраняет его в базу.

        Args:
            message (MessageTextData): Текстовое сообщение для обработки.
            resend_flag (bool): Флаг, указывающий, было ли сообщение отправлено повторно.

        Примечание:
            Если сообщение является повторным и уже содержится в истории, обработка не происходит.
        """
        message_id_old = message.id
        message.id = self._change_perception_for_message_id(message.id)

        # Если это ресенд, то проверяем, есть ли он в темп буфере
        if resend_flag:
            if message.id in self._outbound_message_buffer:
                del self._outbound_message_buffer[message.id]

        self._send_event_data_received(message, resend_flag)
        self._database.save_data([message])
        self._dialog_history_ids.append(message.id)

        # Отправляем ответ
        self._send_recv(MessageData(type=MessageType.Text, message=message_id_old), resend_flag)


    def _change_perception_for_message_id(self, message_id: MessageIdType) -> MessageIdType:
        """
            Изменяет идентификатор сообщения для внутренней обработки.

        Args:
            message_id (MessageIdType): Исходный идентификатор сообщения.

        Returns:
            MessageIdType: Изменённый идентификатор сообщения.
        """
        return message_id.replace('m', 'o') if 'm' in message_id else message_id.replace('o', 'm')

    def _send_event_data_received(self, message: MessageTextData, resend_flag: bool) -> None:
        """
            Отправляет событие о получении данных.

        Args:
            message (MessageTextData): Данные сообщения.
            resend_flag (bool): Флаг повторной отправки.
        """
        self._send_event(NetworkEventType.RECEIVE_DATA, data=message, resend_flag=resend_flag)

    def _send_recv(self, message: MessageData, resend_flag: bool = False) -> None:
        """
            Подготавливает и отправляет сообщение с зашифрованными данными.

        Args:
            message (MessageData): Сообщение для отправки.
            resend_flag (bool): Флаг повторной отправки.
        """
        encrypted_data: EncryptedData = self._crypto.encrypt(message.model_dump_json())
        encrypted_data_b64: B64_FormatData = Encrypter.encode_to_b64(encrypted_data.model_dump_json())
        message_sinature_b64: B64_FormatData = self._crypto.sign_message(encrypted_data_b64)

        data_to_send: NetworkData = NetworkData(
            command_type=NetworkCommands.RECV_DATA,
            encrypted_data=encrypted_data,
            signature=message_sinature_b64,
            additional=AdditionalData(
                resend_flag=resend_flag
            )
        )
        self._send_network_data(data_to_send)

    def _handle_file_message(self, message: MessageFileData) -> None:
        """
            Обрабатывает сообщения с файлами, отправляя событие о получении файла.

        Args:
            message (MessageFileData): Сообщение с файлом для обработки.
        """
        self._send_event_file_received(message)
        # Отправляем ответ
        self._send_recv(MessageData(type=MessageType.File, message=message.filename))
    
    def _send_event_file_received(self, message: MessageFileData) -> None:
        """
            Отправляет событие о получении файла.

        Args:
            message (MessageFileData): Данные файла, которые были получены.
        """
        self._send_event(NetworkEventType.REQUEST_FILE, data=message)
        
    def _handle_recv(self, received_data: NetworkData) -> None:
        """
            Обработка сообщений Recv.

        Args:
            received_data: Полученные данные для Recv
        """
        self._update_ping_time()
        self._logger.debug(f"Получил RECV сообщение от клиента [{self._remote_address}][{self._peer_user_id_hash} | {self._peer_user_name}].")
        
        decrypted_data: MessageData = MessageData.parse_raw(self._crypto.decrypt(received_data.encrypted_data))
        
        match decrypted_data.type:
            case MessageType.Text:
                if not received_data.additional.resend_flag:
                    self._send_event_data_confirmation(self._outbound_message_buffer[decrypted_data.message], received_data.additional.resend_flag) # type: ignore
                    self._database.save_data(messages=[self._outbound_message_buffer[decrypted_data.message]]) # type: ignore
                    self._dialog_history_ids.append(decrypted_data.message) # type: ignore
                del self._outbound_message_buffer[decrypted_data.message] # type: ignore
            case MessageType.File:
                self._send_event_file_confirmation(decrypted_data.message) # type: ignore

    def _send_event_data_confirmation(self, message_id: MessageIdType, resend_flag: bool) -> None:
        """
            Отправляет событие о подтверждении отправки данных.

        Args:
            message_id (MessageIdType): Идентификатор сообщения.
            resend_flag (bool): Флаг, указывающий на повторную отправку.
        """
        self._send_event(NetworkEventType.SEND_DATA, data=message_id, resend_flag=resend_flag)
        
    def _send_event_file_confirmation(self, filename: FilenameType):
        """
            Отправляет событие о подтверждении отправки файла.

        Args:
            filename (FilenameType): Имя файла.
        """
        self._send_event(NetworkEventType.FILE_ACCEPTED, data=filename)
    
    def _handle_sync(self, received_data: NetworkData) -> None:
        """
            Обрабатывает запросы на синхронизацию данных, повторно отправляя необходимые данные.

        Args:
            received_data (NetworkData): Полученные данные для синхронизации.
        """
        self._update_ping_time()
        self._logger.debug(f"Получил SYNC сообщение от клиента [{self._remote_address}][{self._peer_user_id_hash} | {self._peer_user_name}].")
        
        decrypted_data: List[MessageIdType] = json.loads(self._crypto.decrypt(received_data.encrypted_data))

        if not decrypted_data:
            self._logger.debug(f"Пришел пустой запрос SYNC от клиента [{self._remote_address}][{self._peer_user_id_hash} | {self._peer_user_name}].")
            return
                
        self._logger.debug(f"Начинаю отправлять сообщения клиенту [{self._remote_address}][{self._peer_user_id_hash} | {self._peer_user_name}]"
                           f". Всего нужно отправить [{len(decrypted_data)}].")
        
        # Переотправляем N месседжей из истории
        for message in self._dialog_history:
            if message.id in decrypted_data:
                self.send(MessageData(type=MessageType.Text, message=message), is_resended=True)

        self._logger.debug(f"Все [{len(decrypted_data)}] сообщения(-ий) клиенту [{self._remote_address}][{self._peer_user_id_hash} | {self._peer_user_name}] были отправлены.")

    def _send_sync(self, data: str) -> None:
        """
            Отправляет синхронизированные данные клиенту.

        Args:
            data (str): Строка данных для отправки.
        """
        encrypted_data: EncryptedData = self._crypto.encrypt(data)
        encrypted_data_b64: B64_FormatData = Encrypter.encode_to_b64(encrypted_data.model_dump_json())
        message_sinature_b64: B64_FormatData = self._crypto.sign_message(encrypted_data_b64)

        data_to_send: NetworkData = NetworkData(
            command_type=NetworkCommands.SYNC_DATA,
            encrypted_data=encrypted_data,
            signature=message_sinature_b64,
            additional=AdditionalData()
        )
        self._send_network_data(data_to_send)

    def _verify_data(self, data: NetworkData) -> bool:
        """
            Проверяет подлинность полученных данных.

        Args:
            data (NetworkData): Полученные данные для проверки.

        Returns:
            bool: Возвращает True, если данные подлинные, иначе False.
        """
        # Проверяем, что сообщение пришло именно от нашего собеседника
        encrypted_data: EncryptedData = data.encrypted_data
        encrypted_data_b64: B64_FormatData = Encrypter.encode_to_b64(encrypted_data.model_dump_json())

        if not self._crypto.verify_signature(self._peer_rsa_public_key, encrypted_data_b64, data.signature):
            self._logger.warning(f"Пришло поддельное сообщение от имени клиента [{self._remote_address}]"
                                    f"[{data.additional.user_id_hash} | {data.additional.user_name}]!")
            return False

        if data.signature_additional:
            additional_info: AdditionalData = data.additional
            additional_info_b64: B64_FormatData = Encrypter.encode_to_b64(additional_info.model_dump_json())

            if not self._crypto.verify_signature(self._peer_rsa_public_key, additional_info_b64, data.signature_additional):
                self._logger.warning(f"Пришло поддельное сообщение от имени клиента [{self._remote_address}]"
                                    f"[{data.additional.user_id_hash} | {data.additional.user_name}]!")
                return False
        return True

    def _sync_dialog_history(self, peer_dialog_message_ids: List[MessageIdType]) -> None:
        """
            Синхронизирует историю сообщений с удалённым пиром.

        Args:
            peer_dialog_message_ids (List[MessageIdType]): Список идентификаторов сообщений от пира.
        """
        # Если у нас пустая история и у него, то выходим
        if not len(peer_dialog_message_ids) and not len(self._dialog_history):
            return

        # Изменяем идентификаторы сообщений для внутреннего использования.
        # Заменяем префиксы, обозначающие, чьи это сообщения (m-наши, o-его)
        peer_dialog_message_ids = [self._change_perception_for_message_id(mid) for mid in peer_dialog_message_ids]

        # Переотправляем сообщения из временного буфера, если пир их не получил.
        self._resend_messages_from_buffer(peer_dialog_message_ids)

        # Отправляем сообщения, которых нет у пира, но есть в нашей истории.
        self._send_missing_messages(peer_dialog_message_ids)

        # Проверяем, есть ли сообщения у пира, которых нет в нашей истории.
        self._request_missing_messages(peer_dialog_message_ids)

    def _send_missing_messages(self, peer_message_ids: List[MessageIdType]) -> None:
        """
            Отправляет сообщения, которых нет у пира.

        Args:
            peer_message_ids (List[MessageIdType]): Список идентификаторов сообщений от пира.
        """
        missing_messages = [msg for msg in self._dialog_history if msg.id not in peer_message_ids]
        for msg in missing_messages:
            self.send(MessageData(type=MessageType.Text, message=msg), is_resended=True)

    def _request_missing_messages(self, peer_message_ids: List[MessageIdType]) -> None:
        """
            Запрашивает у пира сообщения, которых нет в нашей истории.

        Args:
            peer_message_ids (List[MessageIdType]): Список идентификаторов сообщений от пира.
        """
        if peer_message_ids:
            our_message_ids = [msg_id for msg_id in self._dialog_history_ids]
            missing_peer_messages = [mid for mid in peer_message_ids if mid not in our_message_ids]

            if missing_peer_messages:
                self._logger.debug(f"Запрашиваю отсутствующие сообщения у [{self._remote_address}][{self._peer_user_id_hash} | {self._peer_user_name}].")
                # Возвращаем префиксы, обозначающие, чьи это сообщения (m-наши, o-его)
                missing_peer_messages = [self._change_perception_for_message_id(mid) for mid in missing_peer_messages]
                self._send_sync(json.dumps(missing_peer_messages))

    def _resend_messages_from_buffer(self, peer_message_ids: List[MessageIdType]) -> None:
        """
            Переотправляет сообщения из временного буфера, если пир их не получил.

        Args:
            peer_message_ids (List[MessageIdType]): Список идентификаторов сообщений от пира.
        """
        existed_msg: List[MessageTextData] = []
        for msg_id, msg in list(self._outbound_message_buffer.items()):
            if msg_id not in peer_message_ids:
                self.send(MessageData(type=MessageType.Text, message=msg), is_resended=True)
            else:
                # Иначе просто сохраняем сообщения из буфера в историю
                # Пулим в ивент для обновления истории сообщений
                self._send_event(NetworkEventType.SEND_DATA, data=msg, resend_flag=True, dont_set_flag=True)
                existed_msg.append(msg)
                self._dialog_history_ids.append(msg_id)
                del self._outbound_message_buffer[msg_id]

        if existed_msg:                
            self._event.set()
            # Сохраняем сообщение в бд
            self._database.save_data(existed_msg)
    
    def _handle_exist(self, received_data: NetworkData) -> None:
        """
            Обработка сообщений Exist.

        Args:
            received_data (NetworkData): Полученные данные для Exist
        """
        self._send_event(
            NetworkEventType.ALREADY_EXISTS,
            user_id_hash=received_data.additional.user_id_hash,
            user_name=received_data.additional.user_name
        )
        self.close(silent_mode=True)

    def _send_exist(self) -> None:
        """
            Отправляет сообщение Exist.
        """
        # Кодирование начального сообщения в Base64 и его подпись
        exist_message_b64: B64_FormatData = self._crypto.encrypt_with_rsa('Session already exists!', self._peer_rsa_public_key)
        encrypted_data: EncryptedData = EncryptedData(
                data_b64=exist_message_b64,
                iv_b64=''
        )
        encrypted_data_b64: B64_FormatData = Encrypter.encode_to_b64(encrypted_data.model_dump_json())
        message_signature_b64: B64_FormatData = self._crypto.sign_message(encrypted_data_b64)

        additional_info: AdditionalData = AdditionalData(
            user_id_hash=self._user_id_hash,
            user_name=self._user_name
        )
        additional_info_b64: B64_FormatData = Encrypter.encode_to_b64(additional_info.model_dump_json())
        additional_info_signature_b64: B64_FormatData = self._crypto.sign_message(additional_info_b64)

        # Сборка данных для отправки
        data_to_send = NetworkData(
            command_type=NetworkCommands.EXISTS,
            encrypted_data=encrypted_data,
            signature=message_signature_b64,
            additional=additional_info,
            signature_additional=additional_info_signature_b64
        )
        self._send_network_data(data_to_send)

    def _handle_connecting_to_ourselves(self) -> None:
        """
            Обработка сообщений CONNECTING_TO_OURSELVES.
        """
        # Формирование и отправка сообщения
        self._send_event(NetworkEventType.CONNECTING_TO_OURSELVES)
        self.close(silent_mode=True)

    def _send_connecting_to_ourselves(self) -> None:
            """
                Отправляет сообщение CONNECTING_TO_OURSELVES.
            """
            # Кодирование начального сообщения в Base64 и его подпись
            message_b64: B64_FormatData = self._crypto.encrypt_with_rsa('Connection with ourselves!', self._peer_rsa_public_key)
            encrypted_data: EncryptedData = EncryptedData(
                    data_b64=message_b64,
                    iv_b64=''
            )
            encrypted_data_b64: B64_FormatData = Encrypter.encode_to_b64(encrypted_data.model_dump_json())
            message_signature_b64: B64_FormatData = self._crypto.sign_message(encrypted_data_b64)

            additional_info: AdditionalData = AdditionalData()
            additional_info_b64: B64_FormatData = Encrypter.encode_to_b64(additional_info.model_dump_json())
            additional_info_signature_b64: B64_FormatData = self._crypto.sign_message(additional_info_b64)

            # Сборка данных для отправки
            data_to_send = NetworkData(
                command_type=NetworkCommands.CONNECTING_TO_OURSELVES,
                encrypted_data=encrypted_data,
                signature=message_signature_b64,
                additional=additional_info,
                signature_additional=additional_info_signature_b64
            )
            self._send_network_data(data_to_send)

class ClientManager:
    def __init__(self, logger: Logger, port: PortType = config.NETWORK.CLIENT_COMMUNICATION_PORT) -> None:
        self._logger: Logger = logger
        self._is_active: bool = True
        self._listener_socket = None
        self._listen_communication_port: PortType = port

        self.dht = DHT_Client(listen_port=config.NETWORK.DHT_CLIENT_PORT)
        self.event: NetworkEvent = NetworkEvent()
        self._client_info: ClientInfo = ClientInfo()

        # Список активных сессий
        self._sessions: Dict[int, UserSession] = {}

        self.setup_listener(port)
        threading.Thread(target=self._delete_closed_session, daemon=True).start()

    def setup_listener(self, port: PortType = config.NETWORK.CLIENT_COMMUNICATION_PORT) -> None:
        """
            Настройка и запуск прослушивающего сокета.
        """
        if self._listener_socket is not None:
            self._listener_socket.close()

        # Создаёт новый сокет с использованием интернет-протокола IPv4 (socket.AF_INET) 
        # и TCP (socket.SOCK_STREAM) в качестве транспортного протокола. 
        self._listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

        # Привязывает сокет к IP-адресу и порту. 
        # Пустая строка '' в качестве IP-адреса означает, что сокет будет доступен для всех интерфейсов устройства. 
        self._listener_socket.bind(('', port))

        # 1 указывает максимальное количество необработанных входящих соединений (размер очереди соединений).
        #  Если к серверу попытаются подключиться больше клиентов одновременно, чем указано в этом параметре,
        # дополнительные попытки подключения будут отклонены или оставлены в ожидании, пока не освободится место в очереди.
        self._listener_socket.listen(1)
        self._logger.debug(f"Начинаю прослушивать порт [{port}].")

        self._listen_communication_port: PortType = port
        # Запускаем поток на обработку подключений
        threading.Thread(target=self._accept_connection, daemon=True).start()

    def _accept_connection(self) -> None:
        """
            Обработка входящих подключений.
        """
        if self._listener_socket is None:
            return

        self._logger.debug(f"Ожидаю подключения на порт [{self._listen_communication_port}].")
        while self._is_active:
            try:
                client_socket, addr = self._listener_socket.accept()
                self._logger.debug(f'Создаю новую сессию с [{addr}].')
                session = UserSession(
                    connection_socket=client_socket,
                    remote_address=addr,
                    user_id_hash=self._client_info.user_id_hash,
                    user_name=self._client_info.user_name,
                    user_password=self._client_info.user_password,
                    peer_rsa_public_key='',
                    logger=self._logger,
                    event=self.event
                )
                self._sessions[session.get_id()] = session

            except OSError as e:
                self._logger.debug(f'Завершаю прослушивание порта [{self._listen_communication_port}].')
                return

    def _delete_closed_session(self) -> None:
        """
            Удаляет завершившиеся сессии.
        """
        while self._is_active:
            global session_close_event

            session_close_event.wait()
            session_close_event.clear()

            while not session_close_event.ids.empty():
                event_data = session_close_event.ids.get(block=False)
                if not event_data:
                    break

                if event_data in self._sessions:
                    del self._sessions[event_data]

    def connect(self, peer_info: DHTPeerProfile) -> int:
        """
            Создает новую сессию для взаимодействия с пиром.
        """
        self._logger.debug(f'Создаю новую сессию с [{(peer_info.avaliable_ip, peer_info.avaliable_port)}].')
        session = UserSession(
            connection_socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM),
            remote_address=(peer_info.avaliable_ip, peer_info.avaliable_port),
            user_id_hash=self._client_info.user_id_hash,
            user_name=self._client_info.user_name,
            user_password=self._client_info.user_password,
            peer_rsa_public_key=peer_info.rsa_public_key,
            logger=self._logger,
            event=self.event
        )
        self._sessions[session.get_id()] = session
        return session.connect()

    def close_all_sessions(self) -> None:
        """
            Закрывает все активные соединения.
        """
        self._logger.debug("Закрываю все сессии...")
        # Отправить сообщения всем сессиям о закрытии
        for session in list(self._sessions.values()):
            session.close(logout=True)
        self._logger.debug("Все сессии завершены.")

    def close(self) -> None:
        """
            Закрывает все активные сессии и прослушивающий сокет.
        """
        self._logger.debug(f"Закрываю прослушивающий сокет нашего клиента на порту [{self._listen_communication_port}].")
        self._is_active = False
        if self._listener_socket is not None:
            self._listener_socket.close()

        self._logger.debug("Закрываю все сессии...")
        # Отправить сообщения всем сессиям о закрытии
        for session in list(self._sessions.values()):
            session.close()
        
        self.event.messages.put(
            NetworkEventMessage(
                event_type=NetworkEventType.CLOSE_CLIENT,
                event_data=NetworkEventData()
            )
        )
        self.event.set()
        self._logger.debug("Все сессии завершены.")
    
    def get_state(self) -> bool:
        """Возвращает текущее состояние активности клиента."""
        return self._is_active
    
    def get_session(self, session_id: int) -> UserSession:
        """
            Возвращает объект сессии по ее идентификатору.

        Args:
            session_id: Идентификатор сессии.

        Returns:
            Объект сессии.
        
        Raises:
            UnavailableSessionIdError: Если введен некорректный id сессии.
        """
        if session_id not in self._sessions:
            raise UnavailableSessionIdError('Указанный идентификатор сеанса не существует.')
        return self._sessions[session_id]
    
    def set_client_info(self, client_info: ClientInfo) -> None:
        """
            Устанавливает значения, введенные пользователем.
        Args:
            client_info (ClientInfo): Клиентская информация.
        """
        Encrypter.create_rsa_keys(config.PATHS.KEYS, client_info.user_id_hash, client_info.user_password)
        
        if self._client_info.dht_node_ip != client_info.dht_node_ip or \
            self._client_info.dht_node_port != client_info.dht_node_port or \
                self._client_info.dht_client_port != client_info.dht_client_port:
            self._logger.debug(f'Измению параметры DHT с ip [{self._client_info.dht_node_ip}],'
                               f' порт [{self._client_info.dht_node_port}], порт клиента [{self._client_info.dht_client_port}] на'
                               f' ip [{client_info.dht_node_ip}],'
                               f' порт [{client_info.dht_node_port}], порт клиента [{client_info.dht_client_port}].'
            )
            self._logger.debug(f'Статус DHT [{self.dht.is_active}].')
            self.dht.set_listen_port(client_info.dht_client_port, make_reconnect=False)
            self.dht.reconnect(client_info.dht_node_ip, client_info.dht_node_port) if self.dht.is_active else \
                self.dht.start(client_info.dht_node_ip, client_info.dht_node_port)

        if self._client_info.application_port != client_info.application_port:
            self._logger.debug(f'Переустанавливаю порт прослушивания приложения с [{self._listen_communication_port}] на [{client_info.application_port}].')
            self.setup_listener(client_info.application_port)

        self._client_info = client_info

    def get_ip_address(self) -> str:
        """Возвращает IP-адрес клиента в зависимости от настроек."""
        if self._client_info.use_local_ip:
            return self._get_local_ip_address()
        else:
            return self._get_global_ip_address()

    def _get_local_ip_address(self) -> str:
        """Получает локальный IP адрес клиента."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip_address = s.getsockname()[0]
            self._logger.debug(f"Получен локальный ip адрес [{ip_address}].")
            return ip_address

    def _get_global_ip_address(self) -> str:
        """Получает глобальный IP адрес клиента через внешний сервис."""
        try:
            response = requests.get('https://ifconfig.me')
            ip_address = response.text
            self._logger.debug(f"Получен глобальный ip адрес [{ip_address}].")
            return ip_address
        except requests.RequestException as e:
            self._logger.error(f"Ошибка при получении глобального IP: {e}.")
            return ''
    
@dataclass
class SessionInfo:
    """Хранит информацию о сессии, включая идентификаторы диалога и сессии.
    
    Attributes:
        dialog_id (int): Уникальный идентификатор диалога.
        session_id (int): Уникальный идентификатор сессии.
    """
    dialog_id: int
    session_id: int

class ClientHelper:
    def __init__(self, logger: Logger) -> None:
        self._logger: Logger = logger
        self._client: ClientManager = ClientManager(logger, config.NETWORK.CLIENT_COMMUNICATION_PORT)

        self._active_dialogs: Dict[UserIdHashType, SessionInfo] = {}
        self._inactive_dialogs: Dict[UserIdHashType, SessionInfo] = {}

        self._ip_address: IPAddressType = ''

        self._create_accounts_db()

    def _create_accounts_db(self):
        AccountDatabaseManager.create_database()

    def _create_file_from_data(self, app_root: Any, data: MessageFileData, peer_user_id: str) -> bool:
        """
            Создает файл из переданных данных.

        Args:
            app_root (Any): Ссылка на главное окно (для меседжбокса)
            data (MessageFileData): Данные файла
            peer_user_id (str): Айди пользователя отправителя

        Returns:
            bool: Удалось ли создать файл.
        """
        try:
            os.makedirs(config.PATHS.DOWNLOAD, exist_ok=True)
            with open(os.path.join(config.PATHS.DOWNLOAD, data.filename), 'wb') as file:
                file.write(base64.b64decode(data.raw_data))
            
            self._logger.debug(f'Файл [{data.filename}] успешно получен  от клиента [{peer_user_id}] и записан в папку [{config.PATHS.DOWNLOAD}].')
            CustomMessageBox.show(app_root, 'Успешно', f'Файл [{data.filename}] успешно получен  от клиента [{peer_user_id}] и записан в папку [{config.PATHS.DOWNLOAD}].', CustomMessageType.SUCCESS)
            return True
        except IOError as e:
            self._logger.error(f'Не удалось записать файл [{data.filename}]. Ошибка [{e}].')
            return False

    def get_ip(self) -> IPAddressType:
        """
            Возвращает IP адрес в зависимости от установленного флага. (Локальный или Глобальный)

        Returns:
            IPAddressType: Ip адрес
        """
        self._ip_address = self._client.get_ip_address()
        return self._ip_address
    
    def is_valid_ipv4(self, addr: str) -> bool:
        """
            Проверяет, является ли строка допустимым IPv4 адресом.
        Args:
            addr (str): IPv4 адрес.

        Returns:
            True - если адрес корректен.
        """
        # Регулярное выражение для проверки IPv4
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(pattern, addr):
            # Проверяем, что каждый октет находится в диапазоне от 0 до 255
            return all(0 <= int(part) <= 255 for part in addr.split('.'))
        return False
    
    def is_valid_port(self, port_str: str) -> bool:
        """
            Проверяет, является ли переданная строка корректным портом.

        Args:
        port_str (str): Строка, содержащая порт.

        Returns:
        bool: True если порт корректен, иначе False.
        """
        try:
            # Преобразуем строку в целое число
            port = int(port_str)
            # Проверяем, что порт находится в допустимом диапазоне
            if 1 <= port <= 65535:
                return True
            else:
                return False
        except ValueError:
            # Если преобразование не удалось, строка не является числом
            return False

    def is_port_avaliable(self, port: PortType) -> bool:
        """
        Проверяет доступность порта на локальной машине.
        
        Args:
            port (PortType): Номер порта для проверки.
            
        Returns:
            bool: Возвращает True, если порт доступен, иначе False.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(('127.0.0.1', port))
                # Если bind прошел успешно, порт свободен
                return True
            except socket.error:
                # Если возникла ошибка, порт уже занят
                return False

    def extend_to_32_bytes(self, input_string: str) -> str:
        """
            Дублирует строку до размера в 32 байта.

        Args:
            input_string (str): Входная строка.

        Returns:
            str: Полученная строка размером 32 байта.
        """
        if len(input_string) >= 32:
            return input_string[:32]

        # Вычисляем, сколько раз нужно дублировать исходную строку
        repeat_count = 32 // len(input_string)
        
        # Вычисляем, сколько байт необходимо добавить после дублирования
        remaining_bytes = 32 % len(input_string)

        # Создаем строку, повторяя исходную и добавляя остаток
        return input_string * repeat_count + input_string[:remaining_bytes]

    def generate_random_string(self, number_of_symbols: int = 12) -> UserIdType:
        """
            Генерирует строку из случайных символов.

        Args:
            number_of_symbols (int): Количество символов. По умолчанию 12.

        Returns:
            Строка из случайных символов.
        """
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(number_of_symbols))

    def is_own_ip(self, peer_ip: IPAddressType) -> bool:
        return self._ip_address == peer_ip

    def set_client_info(self, dialog_manager: DialogManager, client_info: ClientInfo) -> None:
        """
            Устанавливает значения, введенные пользователем.
        Args:
            client_info (ClientInfo): Клиентская информация.
        """
        if self._client._client_info.user_id != client_info.user_id:
            try:
                peers_ids_hash = AccountDatabaseManager.fetch_all_peer_id(client_info.user_id_hash)
                history_database = HistoryDatabaseManager(client_info.user_id_hash, client_info.user_password, self._logger)

                for peer_id_hash in peers_ids_hash:
                    history_database.set_table_name(peer_id_hash)
                    history_data, _ = history_database.load_data()

                    if history_data:
                        self._inactive_dialogs[peer_id_hash] = SessionInfo(
                            dialog_id=dialog_manager.add_dialog(
                                dialog_name=peer_id_hash,
                                interlocutor_id=peer_id_hash,
                                dialog_history=history_data
                            ),
                            session_id=-1
                        )
                        dialog_manager.inactivate_dialog(self._inactive_dialogs[peer_id_hash].dialog_id)
            except DatabaseGetDataError as e:
                self._logger.error(f"{e}")

        self._client.set_client_info(client_info)

    def get_hash(self, input_string: str, desired_length: int = 256) -> str:
        """
            Генерирует хэш из строки заданной длины. Хэш функция sha256.

        Args:
            input_string (str): Исходная строка.
            desired_length (int): Количество символов в хэш строке.
        """
        # Создание хэш-объекта SHA-256
        hash_object = hashlib.sha256()
        hash_object.update(input_string.encode('utf-8'))
        
        # Получение шестнадцатеричного дайджеста хэша
        full_hash = hash_object.hexdigest()
        
        # Отрегулируйте длину хэша до желаемой длины
        if desired_length <= len(full_hash):
            # Если желаемая длина меньше фактической длины хэша, обрежьте ее
            return full_hash[:desired_length]
        else:
            # Если желаемая длина больше, расширьте хэш простым способом
            # Здесь мы просто повторяем хэш до тех пор, пока не будет достигнута требуемая длина, а затем усекаем
            extended_hash = (full_hash * ((desired_length // len(full_hash)) + 1))[:desired_length]
            return extended_hash

    def load_user_info(self, user_id: UserIdType, password: str) -> ClientInfo:
        """
            Загружает информацию о пользователе из базы данных.

        Args:
            user_id (UserIdType): ID пользователя.
            password (str): Пароль пользователя.

        Returns:
            ClientInfo: Загруженная информация.
        """
        client_info = ClientInfo(
            user_id=user_id,
            user_password=password
        )

        AccountDatabaseManager.load_user_info(client_info)
        client_info.user_id_hash = self.get_hash(client_info.user_id, len(client_info.user_id) + config.USER_ID_HASH_POSTFIX_SIZE)
        return client_info

    def update_dht_peers_keys(self, dht_peers_keys: DHTNodeHistory) -> None:
        """
            Обновляет список введенных пользователем DHT ключей собеседников.

        Args:
            dht_peers_keys (DHTNodeHistory): Список введенных пользователем DHT ключей собеседников.
        """
        try:
            AccountDatabaseManager.update_dht_peers_keys(
                self._client._client_info.user_id,
                Encrypter.encrypt_with_aes(self._client._client_info.user_password.encode(), dht_peers_keys.model_dump_json())
            )
        except DatabaseSetDataError as e:
            self._logger.error(f'{e}')

    def get_all_registered_users(self) -> list[UserIdType]:
        """
            Возвращает список ID всех зарегистрированных пользователей из базы данных.
        
        Returns:
            list[UserIdType]: Список ID зарегистрированных пользователей.
        """
        try:
            return AccountDatabaseManager.get_all_registered_users()
        except DatabaseGetDataError:
            return []

    def save_account(self) -> None:
        """
            Сохраняет информацию о текущем пользователе в базу данных.
        """
        AccountDatabaseManager.save_user_info(self._client._client_info)

    def update_account(self) -> None:
        """
            Сохраняет информацию о текущем пользователе в базу данных.
        """
        try:
            AccountDatabaseManager.update_user_info(self._client._client_info)
        except DatabaseSetDataError as e:
            self._logger.error(f'{e}')


    def check_password(self, user_id: UserIdType, password: str, expanded: bool = False) -> bool:
        """
            Проверяет введенный пароль на валидность.
        
        Args:
            user_id (UserIdType): ID пользователя.
            password (str): Пароль.
            expanded (bool, optional): Дополнительная проверка: попытается расшифровать все ключа данного пользователя,
              чтобы убедится, что пароль действительно корректен, а не подменен вместе с хэшем. По умолчанию False.

        Returns:
            bool: True - если пароль правильный, иначе False.
        """
        try:
            password_hash = AccountDatabaseManager.load_password_hash(user_id)
        except DatabaseGetDataError as e:
            self._logger.error(f'{e}')
            return False

        if not expanded:
            return password_hash == self.get_hash(password)

        # Проверяем по хэшу
        if password_hash != self.get_hash(password):
            return False
  
        try:
            user_id_hash = self.get_hash(user_id, len(user_id) + config.USER_ID_HASH_POSTFIX_SIZE)
            # Проверяем по RSA ключам
            Encrypter.load_rsa_public_key(config.PATHS.KEYS, user_id_hash, password)

            # Проверяем по расшифровке ключей диалогов
            try:
                all_keys = AccountDatabaseManager.get_all_keys_for_user_id(user_id_hash)
            # Если у нас для него нет ключей диалогов, а всё остальное корректно, то говорим, что это мы.
            except KeyLoadingError:
                return True
            for keys in all_keys:
                Encrypter.decrypt_with_aes(password.encode(), keys[0])
                
        except KeyLoadingError as e:
            self._logger.error(f'{e}')
            return False
        except Exception:
            return False
        return True

    def set_data_to_dht(self, key: str, data: DHTPeerProfile) -> None:
        self._client.dht.set_data(key=key, data=data.model_dump_json())

    def get_data_from_dht(self, key: str) -> DHTPeerProfile:
        return DHTPeerProfile.parse_raw(self._client.dht.get_data(key=key))

    def is_dialog_active(self, peer_user_id_hash: UserIdHashType) -> bool:
        return peer_user_id_hash in self._active_dialogs

    def close_session(self, peer_user_id_hash: UserIdHashType) -> None:
        self._client.get_session(self._active_dialogs[peer_user_id_hash].session_id).close()

    def connect(self, peer_info: DHTPeerProfile) -> None:
        self._client.connect(peer_info)

    def send_message_to_another_client(self, message: MessageData, peer_user_id_hash: UserIdHashType) -> None:
        self._client.get_session(self._active_dialogs[peer_user_id_hash].session_id).send(message)

    def relogin(self) -> None:
        """
            Выходит из текущего аккаунта, закрывая все соединения для данного пользователя.
        """
        self._client.close_all_sessions()
        self._inactive_dialogs = {}

    def handle_dialog(self, app_root: Any, dialogs: DialogManager) -> None:
        """
            Обработчик ивентов для отображения данных.

        Args:
            app_root (Any): Ссылка на главное окно (для меседжбокса)
            dialogs (DialogManager): Ссылка на виджет диалогов.
        """
        while self._client.get_state():
            self._client.event.wait()
            self._client.event.clear()

            while not self._client.event.messages.empty():
                event_data: NetworkEventMessage = self._client.event.messages.get(block=False)
                if not event_data:
                    break

                try:

                    def _show_message(user_id_hash: UserIdHashType, message: MessageTextData):
                        nonlocal dialogs
                        
                        dialog = dialogs.get_dialog(self._active_dialogs[user_id_hash].dialog_id)
                        if not dialog.exist_message(message):
                            dialog.recieve_message(message)

                    match event_data.event_type:
                        case NetworkEventType.CONNECT:
                            if event_data.event_data.user_id_hash in self._inactive_dialogs:
                                dialogs.load_dialog(self._inactive_dialogs[event_data.event_data.user_id_hash].dialog_id)
                                
                                self._active_dialogs[event_data.event_data.user_id_hash] = SessionInfo(
                                    dialog_id=self._inactive_dialogs[event_data.event_data.user_id_hash].dialog_id,
                                    session_id=event_data.event_data.session_id
                                )
                                dialogs.set_dialog_name(
                                    dialog_id=self._active_dialogs[event_data.event_data.user_id_hash].dialog_id,
                                    dialog_name=event_data.event_data.user_name
                                )

                                del self._inactive_dialogs[event_data.event_data.user_id_hash]
                            else:
                                self._active_dialogs[event_data.event_data.user_id_hash] = SessionInfo(
                                    dialog_id=dialogs.add_dialog(
                                        dialog_name=event_data.event_data.user_name,
                                        interlocutor_id=event_data.event_data.user_id_hash,
                                        dialog_history=event_data.event_data.data), # type: ignore
                                    session_id=event_data.event_data.session_id
                                )
                                
                        case NetworkEventType.DISCONNECT:
                            if event_data.event_data.user_id_hash in self._active_dialogs:
                                dialogs.inactivate_dialog(self._active_dialogs[event_data.event_data.user_id_hash].dialog_id)
                                
                                self._inactive_dialogs[event_data.event_data.user_id_hash] = SessionInfo(
                                    dialog_id=self._active_dialogs[event_data.event_data.user_id_hash].dialog_id,
                                    session_id=-1
                                )
                                
                                del self._active_dialogs[event_data.event_data.user_id_hash]

                        case NetworkEventType.LOGOUT:
                            if event_data.event_data.user_id_hash in self._active_dialogs:
                                del self._active_dialogs[event_data.event_data.user_id_hash]

                        case NetworkEventType.SEND_DATA:
                            if event_data.event_data.resend_flag and event_data.event_data.user_id_hash in self._active_dialogs:
                                threading.Thread(target=_show_message, args=(event_data.event_data.user_id_hash, event_data.event_data.data), daemon=True).start()

                        case NetworkEventType.RECEIVE_DATA:
                            if event_data.event_data.user_id_hash in self._active_dialogs:
                                threading.Thread(target=_show_message, args=(event_data.event_data.user_id_hash, event_data.event_data.data), daemon=True).start()
                        
                        case NetworkEventType.REQUEST_FILE:
                            # Пишем файл
                            threading.Thread(target=self._create_file_from_data,
                                            args=(app_root, event_data.event_data.data, event_data.event_data.user_id_hash),
                                            daemon=True).start()
                        case NetworkEventType.FILE_ACCEPTED:
                            self._logger.debug(f'Файл [{event_data.event_data.data}] успешно передан клиенту [{event_data.event_data.user_id_hash}].')# type: ignore
                            CustomMessageBox.show(app_root, 'Успешно', f'Файл [{event_data.event_data.data}] успешно передан клиенту [{event_data.event_data.user_id_hash}].', CustomMessageType.SUCCESS)# type: ignore
                        
                        case NetworkEventType.ALREADY_EXISTS:
                            self._logger.debug(f'Диалог с клиентом [{event_data.event_data.user_id_hash}] от имени [{self._client._client_info.user_id}] уже открыт!')
                            CustomMessageBox.show(app_root, 'Ошибка', f'Диалог с клиентом [{event_data.event_data.user_id_hash}] от имени [{self._client._client_info.user_id}] уже открыт!', CustomMessageType.ERROR)
                        
                        case NetworkEventType.CONNECTING_TO_OURSELVES:
                            self._logger.error("Пока нельзя подключаться самому к себе!")
                            CustomMessageBox.show(app_root, 'Ошибка', "Пока нельзя подключаться самому к себе!", CustomMessageType.ERROR)
                        
                        case NetworkEventType.FAILED_CONNECT:
                            self._logger.debug(f'Не удалось подключиться к клиенту [{event_data.event_data.address}].')
                            CustomMessageBox.show(app_root, 'Ошибка', f'Не удалось подключиться к клиенту [{event_data.event_data.address}].', CustomMessageType.ERROR)
                        
                        case NetworkEventType.UNKNOWN_RSA_PUBLIC_KEY:
                            self._logger.debug(f'Получен неизвестный публичный ключ RSA от клиента [{event_data.event_data.user_id_hash}].')
                            result = YesNoDialog.ask_yes_no(app_root, 'Предупреждение', f'Получен неизвестный публичный ключ RSA от клиента [{event_data.event_data.user_id_hash}].\n\n'
                                                   f'За данным аккаунтом может оказаться злоумышленник, Вы доверяете данному пользователю и хотите начать диалог?')
                            
                            try:
                                self._client.get_session(event_data.event_data.session_id).set_client_decision(result)
                            except UnavailableSessionIdError:
                                CustomMessageBox.show(app_root, 'Ошибка', f'Соединение с клиентом [{event_data.event_data.user_id_hash}] было закрыто из-за неактивности.', CustomMessageType.ERROR)

                        case NetworkEventType.CLOSE_CLIENT:
                            return
                        
                except Exception as e:
                    self._logger.error(f"Произошла ошибка при обработке события. Ошибка [{e}].")

    def close(self):
        """
            Закрывает клиента и dht.
        """
        if self._client.dht.is_active:
            self._client.dht.stop()
        self._client.close()