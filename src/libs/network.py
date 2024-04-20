import base64
from dataclasses import dataclass
from enum import Enum
import json
from logging import Logger
import os
import queue
import re
import socket
import threading
import time
from typing import Any, Dict, List, Tuple, Union
from pydantic import BaseModel, ValidationError
import requests

from config import config, IPAddressType, PortType, FilenameType
from dht import DHT_Client, DHTPeerProfile
from libs.cryptography import B64_FormatData, EncryptedData, Encrypter, PEM_FormatData, RSA_KeyType
from libs.database import DatabaseManager
from libs.message import *
from libs.widgets import CustomMessageBox, CustomMessageType, DialogManager

UserIdType = str

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

class AdditionalData(BaseModel):
    """ Дополнительные данные, связанные с сетевым сообщением. """
    user_id: UserIdType = ''                # Идентификатор пользователя
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

@dataclass
class NetworkEventData:
    """ Хранит данные, связанные с сетевыми событиями. """
    user_id: UserIdType = ''
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
                 user_id: UserIdType, user_name: str, peer_rsa_public_key: RSA_KeyType, logger: Logger, event: NetworkEvent) -> None:
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
        self._user_id: UserIdType = user_id
        self._user_name: str = user_name
        self._peer_user_id: UserIdType = ''  # Идентификатор собеседника
        self._peer_user_name: str = ''  # Имя собеседника
        self._peer_rsa_public_key: RSA_KeyType = peer_rsa_public_key  # Публичный ключ собеседника для проверки подписи
        self._logger: Logger = logger
        self._is_active: bool = True  # Флаг активности сессии
        self._last_ping_time: float = time.time()  # Время последнего пинга
        self._event: NetworkEvent = event

        self._table_name: str = ''  # Имя таблицы для истории сообщений (если применимо)

        self._crypto: Encrypter = Encrypter(keys_path=config.PATHS.KEYS, current_user_id=self._user_id)
        self._database: DatabaseManager = DatabaseManager(user_id=self._user_id, logger=self._logger)

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
            initial_message_b64: B64_FormatData = self._crypto.encode_to_b64(self._crypto.get_rsa_public_key())
            encrypted_data: EncryptedData = EncryptedData(
                data_b64=initial_message_b64,
                iv_b64=''
            )
            encrypted_data_b64: B64_FormatData = self._crypto.encode_to_b64(encrypted_data.model_dump_json())
            message_signature_b64: B64_FormatData = self._crypto.sign_message(encrypted_data_b64)

            additional_info: AdditionalData = AdditionalData(
                user_id=self._user_id,
                user_name=self._user_name,
                ecdh_public_key=self._crypto.get_public_key()  # Получение публичного ключа для обмена
            )
            additional_info_b64: B64_FormatData = self._crypto.encode_to_b64(additional_info.model_dump_json())
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
        encrypted_message_b64: B64_FormatData = self._crypto.encode_to_b64(encrypted_message.model_dump_json())
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
    
    def close(self) -> None:
        """
        Закрывает сессию, отключая соединение и регистрируя событие отключения.

        Закрывает соединение с сокетом и сообщает об отключении с помощью сетевого события.
        Сохраняет неотправленные сообщения в базу данных и завершает поток обработки клиента.
        """
        if self._is_active:
            self._is_active = False
            self._connection_socket.close()  # Закрытие сокета соединения

            # Если есть информация о собеседнике, регистрируем событие отключения
            if self._peer_user_id:
                self._send_event(NetworkEventType.DISCONNECT)
                # Сохранение исходящих сообщений из временного буфера в базу данных
                self._database.save_data(list(self._outbound_message_buffer.values()), is_outbound_message_buffer=True)

                global active_users 
                del active_users[active_users.index(self._peer_user_id)]

            # Ожидание завершения потока обработки клиента, если он был запущен
            try:
                self._thread_client_handler.join()
            except RuntimeError:
                pass  # Игнорирование ошибки, если поток уже завершен

            global session_close_event
            session_close_event.ids.put(self._session_id)
            session_close_event.set()

            # Логирование завершения сессии
            self._logger.debug(f"Сессия для клиента [{self._remote_address}][{self._peer_user_id} "
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
        self._logger.debug(f"Отправил {data.command_type.name} сообщение клиенту [{self._remote_address}][{self._peer_user_id} "
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
                                   f"[{self._peer_user_id} | {self._peer_user_name}] прошла успешно.")

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


            except socket.timeout as e:
                self._logger.debug(f"Клиент не отвечает, закрываю соединение с [{self._remote_address}]"
                                   f"[{self._peer_user_id} | {self._peer_user_name}].")
                self.close()

            except (json.decoder.JSONDecodeError, ValidationError) as e:
                self._logger.error(f'Ошибка при распознании данных. [{e}]')
                self._clear_socket_buffer()
                self._logger.debug(f"Отчищаю буфер сокета для [{self._remote_address}][{self._peer_user_id} | {self._peer_user_name}].")

            except BrokenPipeError:
                self._logger.debug(f'Клиент [{self._remote_address}][{self._peer_user_id} | {self._peer_user_name}] завершил общение. Завершаю сессию.')
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

    def _receive_data(self) -> str:
        """
            Получение данных из сокета с обработкой размера сообщения.

        Raises:
            socket.timeout: Если не удалось получить данные из сокета

        Returns:
            str: Данные из сокета
        """
        raw_data_size: bytes = self._connection_socket.recv(self._int_size_for_message_length)
        if not raw_data_size:
            raise socket.timeout("No data received for the size")
        
        data_size: int = int.from_bytes(raw_data_size, byteorder='big')
        data: str = self._connection_socket.recv(data_size).decode()
        
        if not data:
            raise socket.timeout("No data received for the payload")
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
        if received_data.additional.user_id in active_users:
            self._send_exist()
            self.close()

        self._update_peer_info(received_data)
        self._load_and_send_dialog_history()
        self._send_connetion_event()

    def _update_peer_info(self, received_data: NetworkData) -> None:
        """
            Обновление информации о собеседнике и расчет общего секрета.

        Args:
            received_data (NetworkData): Полученные данные от собеседника
        """
        self._peer_user_id = received_data.additional.user_id
        self._peer_user_name = received_data.additional.user_name
        self._crypto.calculate_dh_secret(received_data.additional.ecdh_public_key)

        active_users.append(self._peer_user_id)

        self._database.set_table_name(self._user_id, self._peer_user_id)

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
        encrypted_message_b64: B64_FormatData = self._crypto.encode_to_b64(encrypted_message.model_dump_json())
        message_signature_b64: B64_FormatData = self._crypto.sign_message(encrypted_message_b64)

        additional_info: AdditionalData = AdditionalData(
            user_id=self._user_id,
            user_name=self._user_name,
            ecdh_public_key=self._crypto.get_public_key()  # Получение публичного ключа для обмена
        )
        additional_info_b64: B64_FormatData = self._crypto.encode_to_b64(additional_info.model_dump_json())
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
        # Формирование и отправка сообщения
        event_message = NetworkEventMessage(
            event_type=event_type,
            event_data=NetworkEventData(
                user_id=self._peer_user_id,
                user_name=self._peer_user_name,
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
        self._logger.debug(f"Получил ACK сообщение от клиента [{self._remote_address}][{self._peer_user_id} | {self._peer_user_name}].")

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
                                   f"[{self._peer_user_id} | {self._peer_user_name}].")

    def _handle_ping(self) -> None:
        """
            Обработка сообщений PING.
        """
        self._update_ping_time()
        self._logger.debug(f"Получил PING сообщение от клиента [{self._remote_address}]"
                                   f"[{self._peer_user_id} | {self._peer_user_name}].")
        self._send_ping_or_pong(NetworkCommands.PONG)
        
    def _send_ping_or_pong(self, message_type: NetworkCommands) -> None:
        """
            Отправляет Ping или Pong сообщение в зависимости от переданного аргумента.
        Args:
            message_type (NetworkCommands): Тип сообщения (Ping или Pong)
        """
        encrypted_message: EncryptedData = self._crypto.encrypt(message_type.name)
        encrypted_message_b64: B64_FormatData = self._crypto.encode_to_b64(encrypted_message.model_dump_json())
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
                                   f"[{self._peer_user_id} | {self._peer_user_name}].")

    def _handle_send(self, received_data: NetworkData) -> None:
        """
            Обработка сообщений Send.

        Args:
            received_data (NetworkData): Полученные данные для Send
        """
        self._update_ping_time()
        self._logger.debug(f"Получил SEND сообщение от клиента [{self._remote_address}][{self._peer_user_id} | {self._peer_user_name}].")
        
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
        encrypted_data_b64: B64_FormatData = self._crypto.encode_to_b64(encrypted_data.model_dump_json())
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
        self._logger.debug(f"Получил RECV сообщение от клиента [{self._remote_address}][{self._peer_user_id} | {self._peer_user_name}].")
        
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
        self._logger.debug(f"Получил SYNC сообщение от клиента [{self._remote_address}][{self._peer_user_id} | {self._peer_user_name}].")
        
        decrypted_data: List[MessageIdType] = json.loads(self._crypto.decrypt(received_data.encrypted_data))

        if not decrypted_data:
            self._logger.debug(f"Пришел пустой запрос SYNC от клиента [{self._remote_address}][{self._peer_user_id} | {self._peer_user_name}].")
            return
                
        self._logger.debug(f"Начинаю отправлять сообщения клиенту [{self._remote_address}][{self._peer_user_id} | {self._peer_user_name}]"
                           f". Всего нужно отправить [{len(decrypted_data)}].")
        
        # Переотправляем N месседжей из истории
        for message in self._dialog_history:
            if message.id in decrypted_data:
                self.send(MessageData(type=MessageType.Text, message=message), is_resended=True)

        self._logger.debug(f"Все [{len(decrypted_data)}] сообщения(-ий) клиенту [{self._remote_address}][{self._peer_user_id} | {self._peer_user_name}] были отправлены.")

    def _send_sync(self, data: str) -> None:
        """
            Отправляет синхронизированные данные клиенту.

        Args:
            data (str): Строка данных для отправки.
        """
        encrypted_data: EncryptedData = self._crypto.encrypt(data)
        encrypted_data_b64: B64_FormatData = self._crypto.encode_to_b64(encrypted_data.model_dump_json())
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
        encrypted_data_b64: B64_FormatData = self._crypto.encode_to_b64(encrypted_data.model_dump_json())

        if not self._crypto.verify_signature(self._peer_rsa_public_key, encrypted_data_b64, data.signature):
            self._logger.warning(f"Пришло поддельное сообщение от имени клиента [{self._remote_address}]"
                                    f"[{data.additional.user_id} | {data.additional.user_name}]!")
            return False

        if data.signature_additional:
            additional_info: AdditionalData = data.additional
            additional_info_b64: B64_FormatData = self._crypto.encode_to_b64(additional_info.model_dump_json())

            if not self._crypto.verify_signature(self._peer_rsa_public_key, additional_info_b64, data.signature_additional):
                self._logger.warning(f"Пришло поддельное сообщение от имени клиента [{self._remote_address}]"
                                    f"[{data.additional.user_id} | {data.additional.user_name}]!")
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
                self._logger.debug(f"Запрашиваю отсутствующие сообщения у [{self._remote_address}][{self._peer_user_id} | {self._peer_user_name}].")
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
        # Формирование и отправка сообщения
        event_message = NetworkEventMessage(
            event_type=NetworkEventType.ALREADY_EXISTS,
            event_data=NetworkEventData(
                user_id=received_data.additional.user_id,
                user_name=received_data.additional.user_name,
                address=self._remote_address
            )
        )
        self._event.messages.put(event_message)
        self._event.set()
        self.close()

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
        encrypted_data_b64: B64_FormatData = self._crypto.encode_to_b64(encrypted_data.model_dump_json())
        message_signature_b64: B64_FormatData = self._crypto.sign_message(encrypted_data_b64)

        additional_info: AdditionalData = AdditionalData(
            user_id=self._user_id,
            user_name=self._user_name
        )
        additional_info_b64: B64_FormatData = self._crypto.encode_to_b64(additional_info.model_dump_json())
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

class ClientManager:
    def __init__(self, logger: Logger, port: PortType = config.NETWORK.CLIENT_COMMUNICATION_PORT) -> None:
        self._logger: Logger = logger
        self._is_active: bool = True
        self._listen_communication_port: PortType = port

        self.event: NetworkEvent = NetworkEvent()

        self._user_id: UserIdType = ''
        self._user_name: str = ''
        self._use_local_ip: bool = False

        self.is_dht_active = False

        # Список активных сессий
        self._sessions: Dict[int, UserSession] = {}

        self._setup_listener()
        threading.Thread(target=self._connect_to_dht, daemon=True).start()
        threading.Thread(target=self._delete_closed_session, daemon=True).start()

    def _setup_listener(self) -> None:
        """
            Настройка и запуск прослушивающего сокета.
        """
        # Создаёт новый сокет с использованием интернет-протокола IPv4 (socket.AF_INET) 
        # и TCP (socket.SOCK_STREAM) в качестве транспортного протокола. 
        self._listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

        # Привязывает сокет к IP-адресу и порту. 
        # Пустая строка '' в качестве IP-адреса означает, что сокет будет доступен для всех интерфейсов устройства. 
        self._listener_socket.bind(('', self._listen_communication_port))

        # 1 указывает максимальное количество необработанных входящих соединений (размер очереди соединений).
        #  Если к серверу попытаются подключиться больше клиентов одновременно, чем указано в этом параметре,
        # дополнительные попытки подключения будут отклонены или оставлены в ожидании, пока не освободится место в очереди.
        self._listener_socket.listen(1)
        self._logger.debug(f"Начинаю прослушивать порт [{self._listen_communication_port}].")

        # Запускаем поток на обработку подключений
        threading.Thread(target=self._accept_connection, daemon=True).start()

    def _accept_connection(self) -> None:
        """
            Обработка входящих подключений.
        """
        self._logger.debug(f"Ожидаю подключения на порт [{self._listen_communication_port}].")
        while self._is_active:
            try:
                client_socket, addr = self._listener_socket.accept()
                self._logger.debug(f'Создаю новую сессию с [{addr}].')
                session = UserSession(
                    connection_socket=client_socket,
                    remote_address=addr,
                    user_id=self._user_id,
                    user_name=self._user_name,
                    peer_rsa_public_key='',
                    logger=self._logger,
                    event=self.event
                )
                self._sessions[session.get_id()] = session

            except OSError as e:
                self._logger.debug(f'Завершаю прослушивание порта [{self._listen_communication_port}].')

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

    def _connect_to_dht(self):
        """
            Подключаемся к DHT.
        """
        self._logger.debug('Подключаюсь к DHT...')
        self.dht = DHT_Client(
            listen_port=config.NETWORK.DHT.PORT - 1,
            dht_ip=config.NETWORK.DHT.IP,
            dht_port=config.NETWORK.DHT.PORT
        )
        self.is_dht_active = True

    def connect(self, peer_info: DHTPeerProfile) -> int:
        """
            Создает новую сессию для взаимодействия с пиром.
        """
        self._logger.debug(f'Создаю новую сессию с [{(peer_info.avaliable_ip, peer_info.avaliable_port)}].')
        session = UserSession(
            connection_socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM),
            remote_address=(peer_info.avaliable_ip, peer_info.avaliable_port),
            user_id=self._user_id,
            user_name=self._user_name,
            peer_rsa_public_key=peer_info.rsa_public_key,
            logger=self._logger,
            event=self.event
        )
        self._sessions[session.get_id()] = session
        return session.connect()

    def close(self) -> None:
        """
            Закрывает все активные сессии и прослушивающий сокет.
        """
        self._logger.debug(f"Закрываю прослушивающий сокет нашего клиента на порту [{self._listen_communication_port}].")
        self._is_active = False
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
    
    def set_client_info(self, user_id: UserIdType, user_name: str, use_local_ip: bool):
        """Устанавливает значения, введенные пользователем."""
        self._user_id = user_id
        self._user_name = user_name
        self._use_local_ip = use_local_ip

        Encrypter.create_rsa_keys(config.PATHS.KEYS, self._user_id)

    def get_ip_address(self) -> str:
        """Возвращает IP-адрес клиента в зависимости от настроек."""
        if self._use_local_ip:
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
    
    def is_ipv4(self, addr: str) -> bool:
        """Проверяет, является ли строка допустимым IPv4 адресом."""
        # Регулярное выражение для проверки IPv4
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(pattern, addr):
            # Проверяем, что каждый октет находится в диапазоне от 0 до 255
            return all(0 <= int(part) <= 255 for part in addr.split('.'))
        return False
    
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

        self._active_dialogs: Dict[UserIdType, SessionInfo] = {}
        self._inactive_dialogs: Dict[UserIdType, SessionInfo] = {}

        self._ip_address: IPAddressType = ''

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
    
    def is_own_ip(self, peer_ip: IPAddressType) -> bool:
        return self._ip_address == peer_ip

    def set_client_info(self, user_id: UserIdType, user_name: str, use_local_ip: bool):
        """
            Устанавливает значения, введенные пользователем.
        """
        self._client.set_client_info(user_id, user_name, use_local_ip)

    def set_data_to_dht(self, key: str, data: DHTPeerProfile) -> None:
        self._client.dht.set_data(key=key, data=data.model_dump_json())

    def get_data_from_dht(self, key: str) -> DHTPeerProfile:
        return DHTPeerProfile.parse_raw(self._client.dht.get_data(key=key))

    def is_dialog_active(self, peer_user_id: UserIdType) -> bool:
        return peer_user_id in self._active_dialogs

    def close_session(self, peer_user_id: UserIdType) -> None:
        self._client.get_session(self._active_dialogs[peer_user_id].session_id).close()

    def connect(self, peer_info: DHTPeerProfile) -> None:
        self._client.connect(peer_info)

    def send_message_to_another_client(self, message: MessageData, peer_user_id: UserIdType) -> None:
        self._client.get_session(self._active_dialogs[peer_user_id].session_id).send(message)

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

                    def _show_message(user_id: UserIdType, message: MessageTextData):
                        nonlocal dialogs
                        
                        dialog = dialogs.get_dialog(self._active_dialogs[user_id].dialog_id)
                        if not dialog.exist_message(message):
                            dialog.recieve_message(message)

                    match event_data.event_type:
                        case NetworkEventType.CONNECT:
                            if event_data.event_data.user_id in self._inactive_dialogs:
                                dialogs.load_dialog(self._inactive_dialogs[event_data.event_data.user_id].dialog_id)
                                
                                self._active_dialogs[event_data.event_data.user_id] = SessionInfo(
                                    dialog_id=self._inactive_dialogs[event_data.event_data.user_id].dialog_id,
                                    session_id=event_data.event_data.session_id
                                )

                                del self._inactive_dialogs[event_data.event_data.user_id]
                            else:
                                self._active_dialogs[event_data.event_data.user_id] = SessionInfo(
                                    dialog_id=dialogs.add_dialog(
                                        dialog_name=event_data.event_data.user_name,
                                        interlocutor_id=event_data.event_data.user_id,
                                        dialog_history=event_data.event_data.data), # type: ignore
                                    session_id=event_data.event_data.session_id
                                )
                                
                        case NetworkEventType.DISCONNECT:
                            # self._chats.hide_dialog(self._active_dialogs[event_data[Event.EVENT_CONNECT][0]])
                            if event_data.event_data.user_id in self._active_dialogs:
                                dialogs.inactivate_dialog(self._active_dialogs[event_data.event_data.user_id].dialog_id)
                                
                                self._inactive_dialogs[event_data.event_data.user_id] = SessionInfo(
                                    dialog_id=self._active_dialogs[event_data.event_data.user_id].dialog_id,
                                    session_id=-1
                                )
                                
                                del self._active_dialogs[event_data.event_data.user_id]

                        case NetworkEventType.SEND_DATA:
                            if event_data.event_data.resend_flag and event_data.event_data.user_id in self._active_dialogs:
                                threading.Thread(target=_show_message, args=(event_data.event_data.user_id, event_data.event_data.data), daemon=True).start()

                        case NetworkEventType.RECEIVE_DATA:
                            if event_data.event_data.user_id in self._active_dialogs:
                                threading.Thread(target=_show_message, args=(event_data.event_data.user_id, event_data.event_data.data), daemon=True).start()
                        
                        case NetworkEventType.REQUEST_FILE:
                            # Пишем файл
                            threading.Thread(target=self._create_file_from_data,
                                            args=(app_root, event_data.event_data.data, event_data.event_data.user_id),
                                            daemon=True).start()
                        case NetworkEventType.FILE_ACCEPTED:
                            self._logger.debug(f'Файл [{event_data.event_data.data.filename}] успешно передан клиенту [{event_data.event_data.user_id}].')# type: ignore
                            CustomMessageBox.show(app_root, 'Успешно', f'Файл [{event_data.event_data.data.filename}] успешно передан клиенту [{event_data.event_data.user_id}].', CustomMessageType.SUCCESS)# type: ignore
                        case NetworkEventType.ALREADY_EXISTS:
                            self._logger.debug(f'Диалог с клиентом [{event_data.event_data.user_id}] от имени [{self._client._user_id}] уже открыт!')
                            CustomMessageBox.show(app_root, 'Внимание', f'Диалог с клиентом [{event_data.event_data.user_id}] от имени [{self._client._user_id}] уже открыт!', CustomMessageType.WARNING)
                        case NetworkEventType.CLOSE_CLIENT:
                            return
                except Exception as e:
                    self._logger.error(f"Произошла ошибка при обработке события. Ошибка [{e}].")

    def close(self):
        """
            Закрывает клиента и dht.
        """
        if self._client.is_dht_active:
            self._client.dht.stop()
        self._client.close()