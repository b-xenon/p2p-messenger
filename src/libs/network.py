import time
import json
import socket
import queue
import threading
from logging import Logger

import config

class Message:
    MESSAGE_INIT = "0"
    MESSAGE_ACK = "1"

    MESSAGE_PING = "2"
    MESSAGE_PONG = "3"

    MESSAGE_SEND_DATA = "4"
    MESSAGE_RECV_DATA = "5"

    MESSAGE_SYNC_DATA = "6"
    MESSAGE_SYNC_SEND_DATA = "7"
    MESSAGE_SYNC_RECV_DATA = "8"


class Event(threading.Event):
    EVENT_CONNECT = 0
    EVENT_DISCONNECT = 1
    EVENT_CLOSE = 2

    EVENT_ADD_RECV_DATA = 3
    EVENT_ADD_SEND_DATA = 4

    def __init__(self) -> None:
        super().__init__()
        self.data = queue.Queue()

class Session:
    session_counter = 0

    def __init__(self, socket: socket.socket, address: tuple, logger: Logger, event: Event) -> None:
        self._socket = socket
        self._address = address
        self._logger = logger
        self._session_is_active = True
        self._last_ping_time = time.time()
        self._event = event

        self._session_id = Session.session_counter
        Session.session_counter += 1

        self._dialog_history = []
        self._temp_buffer_of_our_messages = {}

        self._int_size_for_message_len = 4

        self._thread_client_handler = threading.Thread(target=self._handle_client, daemon=True)
        self._thread_client_handler.start()

    def get_id(self) -> int:
        return self._session_id

    def connect(self) -> int:
        try:
            self._logger.debug(f"Устанавливаю соединение с клиентом [{self._address}].")
            
            self._socket.connect(self._address)

            data_to_send = json.dumps({Message.MESSAGE_INIT: {
                'data': 555
            }}).encode()
            # Отправляем Init
            self._socket.sendall(len(data_to_send).to_bytes(self._int_size_for_message_len, byteorder='big') + data_to_send)

            self._logger.debug(f"Отправил Init сообщение клиенту [{self._address}].")
            return self._session_id
        
        except OSError:
            self._logger.debug(f'Произошло закрытие сокета. Завершаю сессию.')
            return -1

    def send(self, message: dict) -> None:
        self._logger.debug(f"Отправляю Send сообщение клиенту [{self._address}].")

        # Отправляем идентификатор сообщения
        data_to_send = json.dumps({Message.MESSAGE_SEND_DATA: message}).encode()
        # Отправляем Send
        self._socket.sendall(len(data_to_send).to_bytes(self._int_size_for_message_len, byteorder='big') + data_to_send)

        self._logger.debug(f"Отправил SEND сообщение клиенту [{self._address}].")

        self._temp_buffer_of_our_messages[message['msg_id']] = message

    def _encode(self, data: str) -> str:
        return data

    def _decode(self, data: str) -> str:
        return data
    
    def _load_dialog_history(self) -> None:
        pass

    def _save_message_in_db(self, message: dict) -> None:
        pass

    def _handle_client(self) -> None:
        # Использование метода settimeout(ping_timeout) для сокета client_socket в контексте 
        # TCP-соединений устанавливает таймаут на блокирующие операции сокета, такие как recv() и send().
        # Это значит, что операция будет ждать данных или возможности отправки данных в течение указанного времени
        # (ping_timeout), и если за это время не произойдет никаких действий, то операция завершится с исключением socket.timeout.
        self._load_dialog_history()
        
        self._socket.settimeout(config.PING_TIMEOUT)
        self._logger.debug(f"Устанавливаю таймаут [{config.PING_TIMEOUT}] для клиента [{self._address}].")
        
        ping_thread = threading.Thread(target=self._send_ping, daemon=True)

        while self._session_is_active:
            try:
                # Получаем данные из сокета и переводим байтовую строку в Unicode для python
                # Считываем n байт, которые указывают на длину нужного сообщения
                data_size = self._socket.recv(self._int_size_for_message_len)
                if not data_size:
                    raise socket.timeout
                
                # Распаршиваем длину
                data_size = int.from_bytes(data_size, byteorder='big')
                # Считыаем данные
                data = self._socket.recv(data_size).decode()
                
                if not data:
                    raise socket.timeout

                json_data = json.loads(data)

                if Message.MESSAGE_INIT in json_data:
                    self._last_ping_time = time.time()      # Обновляем время последнего пинга
                    self._logger.debug(f"Получил Init сообщение от клиента [{self._address}].")

                    data_to_send = json.dumps({Message.MESSAGE_ACK: {
                        'data': 123
                    }}).encode()
                    # Отправляем ответ на Init
                    self._socket.sendall(len(data_to_send).to_bytes(self._int_size_for_message_len, byteorder='big') + data_to_send)
                    
                    self._event.data.put({Event.EVENT_CONNECT: self._address})
                    self._event.set()

                    self._logger.debug(f"Отправил Ack сообщение клиенту [{self._address}].")
                
                elif Message.MESSAGE_ACK in json_data:
                    self._last_ping_time = time.time()      # Обновляем время последнего пинга
                    self._logger.debug(f"Получил Ack сообщение от клиента [{self._address}].")

                    self._event.data.put({Event.EVENT_CONNECT: self._address})
                    self._event.set()

                    ping_thread.start()

                elif Message.MESSAGE_PING in json_data:
                    self._last_ping_time = time.time()      # Обновляем время последнего пинга
                    self._logger.debug(f"Получил Ping сообщение от клиента [{self._address}].")

                    data_to_send = json.dumps({Message.MESSAGE_PONG: None}).encode()
                    # Отправляем ответ на Ping
                    self._socket.sendall(len(data_to_send).to_bytes(self._int_size_for_message_len, byteorder='big') + data_to_send)

                    self._logger.debug(f"Отправил Pong сообщение клиенту [{self._address}].")

                elif Message.MESSAGE_PONG in json_data:
                    self._last_ping_time = time.time()      # Обновляем время последнего пинга
                    self._logger.debug(f"Получил Pong сообщение от клиента [{self._address}].")

                elif Message.MESSAGE_SEND_DATA in json_data:
                    self._last_ping_time = time.time()      # Обновляем время последнего пинга
                    self._logger.debug(f"Получил Send сообщение от клиента [{self._address}].")

                    json_data[Message.MESSAGE_SEND_DATA]['msg_id'].replace('m', 'o')

                    # Пулим в ивент для обновления истории сообщений
                    self._event.data.put({Event.EVENT_ADD_RECV_DATA: {
                        'addr': self._address,
                        'data': json_data[Message.MESSAGE_SEND_DATA]
                    }})
                    self._event.set()

                    # Сохраняем сообщение в бд
                    self._save_message_in_db(json_data[Message.MESSAGE_SEND_DATA])

                    # Отправляем идентификатор сообщения
                    data_to_send = json.dumps({Message.MESSAGE_RECV_DATA: json_data[Message.MESSAGE_SEND_DATA]['msg_id']}).encode()
                    # Отправляем Recv
                    self._socket.sendall(len(data_to_send).to_bytes(self._int_size_for_message_len, byteorder='big') + data_to_send)

                    self._logger.debug(f"Отправил RECV сообщение клиенту [{self._address}].")

                elif Message.MESSAGE_RECV_DATA in json_data:
                    self._last_ping_time = time.time()      # Обновляем время последнего пинга
                    self._logger.debug(f"Получил RECV сообщение от клиента [{self._address}].")

                    # Пулим в ивент для обновления истории сообщений
                    self._event.data.put({Event.EVENT_ADD_SEND_DATA: {
                        'addr': self._address,
                        'data': self._temp_buffer_of_our_messages[json_data[Message.MESSAGE_RECV_DATA]]
                    }})
                    self._event.set()

                    # Сохраняем сообщение в бд
                    self._save_message_in_db(self._temp_buffer_of_our_messages[json_data[Message.MESSAGE_RECV_DATA]])

                    del self._temp_buffer_of_our_messages[json_data[Message.MESSAGE_RECV_DATA]]

            
                elif Message.MESSAGE_SYNC_DATA in json_data:
                    pass

                
                elif Message.MESSAGE_SYNC_SEND_DATA in json_data:
                    pass

            
                elif Message.MESSAGE_SYNC_RECV_DATA in json_data:
                    pass

            except socket.timeout as e:
                self._logger.debug(f"Клиент не отвечает, закрываю соединение с [{self._address}].")
                self.close()

            except json.decoder.JSONDecodeError as e:
                self._logger.error(f'Ошибка при распознании данных. Данные: [{data}]')
                self._clear_socket_buffer()
                self._logger.debug(f"Отчищаю буфер сокета для [{self._address}].")

            except BrokenPipeError:
                self._logger.debug(f'Клиент [{self._address}] завершил общение. Завершаю сессию.')
                self.close()

            except OSError:
                self._logger.debug(f'Произошло закрытие сокета. Завершаю сессию.')
                self.close()


    def _send_ping(self) -> None:
        while self._session_is_active:
            while self._session_is_active and time.time() - self._last_ping_time < config.PING_INTERVAL:
                time.sleep(0.1)
            try:
                data_to_send = json.dumps({Message.MESSAGE_PING: None}).encode()
                # Отправляем Ping
                self._socket.sendall(len(data_to_send).to_bytes(self._int_size_for_message_len, byteorder='big') + data_to_send)
                self._logger.debug(f"Отправил Ping сообщение клиенту [{self._address}].")
            except OSError:
                self._logger.debug(f"Не удалось отправить пинг клиенту [{self._address}].")


    def _clear_socket_buffer(self):
        self._socket.setblocking(False)  # Установка сокета в неблокирующий режим
        try:
            while True:
                data = self._socket.recv(1024)  # Попытка прочитать данные из сокета
                if not data:
                    break  # Если данных нет, выходим из цикла
        except BlockingIOError:
            pass  # Игнорируем ошибку блокировки, потому что это означает, что буфер пуст
        finally:
            self._socket.setblocking(True)  # Возвращаем сокет в блокирующий режим


    def close(self):
        self._session_is_active = False
        self._socket.close()

        self._event.data.put({Event.EVENT_DISCONNECT: self._address})
        self._event.set()
       
        try:
            self._thread_client_handler.join()
        except RuntimeError:
            pass

        self._logger.debug(f"Сессия для клиента [{self._address}] завершена.")


class Client:
    def __init__(self, logger: Logger, port: int = config.PORT_CLIENT_COMMUNICATION) -> None:
        self._client_state_is_active = True
        self._listen_communication_port = port
        self._logger = logger
        self.event = Event()

        # Список активных сессий
        self._sessions = {}

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
        self._logger.debug(f"Ожидаю подключения на порт [{self._listen_communication_port}].")
        while self._client_state_is_active:
            try:
                client_socket, addr = self._listener_socket.accept()
                self._logger.debug(f'Создаю новую сессию с [{addr}].')
                s = Session(client_socket, addr, self._logger, self.event)
                self._sessions[s.get_id()] = s

            except OSError as e:
                self._logger.debug(f'Завершаю прослушивание порта [{self._listen_communication_port}].')

    def connect(self, interlocutor_ip: str, port: int = config.PORT_CLIENT_COMMUNICATION) -> int:
        self._logger.debug(f'Создаю новую сессию с [{(interlocutor_ip, port)}].')
        s = Session(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM),
            (interlocutor_ip, port),
            self._logger,
            self.event
        )
        self._sessions[s.get_id()] = s
        return s.connect()

    def close(self) -> None:
        self._logger.debug(f"Закрываю прослушивающий сокет нашего клиента на порту [{self._listen_communication_port}].")
        self._client_state_is_active = False
        self._listener_socket.close()

        self._logger.debug("Закрываю все сессии...")
        # Отправить сообщения всем сессиям о закрытии
        for session in self._sessions.values():
            session.close()
        
        self.event.data.put({Event.EVENT_CLOSE: None})
        self.event.set()
        self._logger.debug("Все сессии завершены.")
    
    def get_state(self) -> bool:
        return self._client_state_is_active
    
    def get_session(self, session_id) -> Session:
        if session_id not in self._sessions:
            return None
        return self._sessions[session_id]