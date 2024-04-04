import time
import json
import socket
import threading
from logging import Logger

import config

class Session:
    def __init__(self, socket: socket.socket, address: tuple, logger: Logger) -> None:
        self._socket = socket
        self._address = address
        self._logger = logger
        self._session_is_active = True
        self._last_ping_time = time.time()

        self._listen_port_communication = config.PORT_CLIENT_COMMUNICATION
        # self._listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # self._listener_socket.bind(('', self._listen_port_communication))
        # self._listener_socket.listen(1)
        # self._logger.debug(f"Начинаю прослушивать порт [{self._listen_port_connection_checking}].")

        self._thread_connection_checking = threading.Thread(target=self._handle_client, daemon=True)
        self._thread_connection_checking.start()

    def connect(self) -> bool:
        try:
            self._logger.debug(f"Устанавливаю соединение с клиентом [{self._address}].")
            
            self._socket.connect(self._address)

            data_to_send = json.dumps({config.MESSAGE_INIT: {
                'data': 555
            }}).encode()
            self._socket.sendall(data_to_send)      # Отправляем Init

            self._logger.debug(f"Отправил Init сообщение клиенту [{self._address}].")
            return True
        
        except OSError:
            self._logger.debug(f'Произошло закрытие сокета. Завершаю сессию.')
            return False

    def _handle_client(self) -> None:
        # Использование метода settimeout(ping_timeout) для сокета client_socket в контексте 
        # TCP-соединений устанавливает таймаут на блокирующие операции сокета, такие как recv() и send().
        # Это значит, что операция будет ждать данных или возможности отправки данных в течение указанного времени
        # (ping_timeout), и если за это время не произойдет никаких действий, то операция завершится с исключением socket.timeout.
        self._socket.settimeout(config.PING_TIMEOUT)
        self._logger.debug(f"Устанавливаю таймаут [{config.PING_TIMEOUT}] для клиента [{self._address}].")

        while self._session_is_active:
            try:
                # Получаем данные из сокета (до 1024 байт) и переводим байтовую строку в Unicode для python
                data = self._socket.recv(1024)
                if data:
                    json_data = json.loads(data.decode())

                    if config.MESSAGE_INIT in json_data:
                        self._last_ping_time = time.time()      # Обновляем время последнего пинга
                        self._logger.debug(f"Получил Init сообщение от клиента [{self._address}].")

                        data_to_send = json.dumps({config.MESSAGE_ACK: {
                            'data': 123
                        }}).encode()
                        self._socket.sendall(data_to_send)      # Отправляем ответ на Init
                        
                        self._create_connection_for_communication()

                        self._logger.debug(f"Отправил Ack сообщение клиенту [{self._address}].")
                    
                    elif config.MESSAGE_ACK in json_data:
                        self._last_ping_time = time.time()      # Обновляем время последнего пинга
                        self._logger.debug(f"Получил Ack сообщение от клиента [{self._address}].")

                        self._create_connection_for_communication()
                        self._send_ping()

                    elif config.MESSAGE_PING in json_data:
                        self._last_ping_time = time.time()      # Обновляем время последнего пинга
                        self._logger.debug(f"Получил Ping сообщение от клиента [{self._address}].")

                        data_to_send = json.dumps({config.MESSAGE_PONG: None}).encode()
                        self._socket.sendall(data_to_send)      # Отправляем ответ на Ping

                        self._logger.debug(f"Отправил Pong сообщение клиенту [{self._address}].")

                    elif config.MESSAGE_PONG in json_data:
                        self._last_ping_time = time.time()      # Обновляем время последнего пинга
                        self._logger.debug(f"Получил Pong сообщение от клиента [{self._address}].")

                        self._send_ping()
                    
            except socket.timeout as e:
                self._logger.debug(f"Клиент не отвечает, закрываю соединение с [{self._address}].")
                self.close()

            except json.decoder.JSONDecodeError as e:
                self._logger.error(f'Ошибка при распознании данных. Данные: [{data}]')

            except BrokenPipeError:
                self._logger.debug(f'Клиент [{self._address}] завершил общение. Завершаю сессию.')
                self.close()

            except OSError:
                self._logger.debug(f'Произошло закрытие сокета. Завершаю сессию.')
                self.close()


    def _send_ping(self) -> None:
        while self._session_is_active and time.time() - self._last_ping_time < config.PING_INTERVAL:
            time.sleep(0.1)

        data_to_send = json.dumps({config.MESSAGE_PING: None}).encode()
        self._socket.sendall(data_to_send)      # Отправляем Ping
        self._logger.debug(f"Отправил Ping сообщение клиенту [{self._address}].")


    def _create_connection_for_communication(self):
        pass

    def close(self):
        self._session_is_active = False
        self._socket.close()
       
        try:
            self._thread_connection_checking.join()
        except RuntimeError:
            pass

        self._logger.debug(f"Сессия для клиента [{self._address}] завершена.")

        # TODO
        # добавить сохранение в БД


class Client:
    def __init__(self, logger: Logger) -> None:
        self._client_state_is_active = True
        self._listen_port_connection_checking = config.PORT_CLIENT_CONNECTION_CHECKING
        self._logger = logger

        # Список активных сессий
        self._sessions = []

        # Создаёт новый сокет с использованием интернет-протокола IPv4 (socket.AF_INET) 
        # и TCP (socket.SOCK_STREAM) в качестве транспортного протокола. 
        self._listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

        # Привязывает сокет к IP-адресу и порту. 
        # Пустая строка '' в качестве IP-адреса означает, что сокет будет доступен для всех интерфейсов устройства. 
        self._listener_socket.bind(('', self._listen_port_connection_checking))

        # 1 указывает максимальное количество необработанных входящих соединений (размер очереди соединений).
        #  Если к серверу попытаются подключиться больше клиентов одновременно, чем указано в этом параметре,
        # дополнительные попытки подключения будут отклонены или оставлены в ожидании, пока не освободится место в очереди.
        self._listener_socket.listen(1)
        self._logger.debug(f"Начинаю прослушивать порт [{self._listen_port_connection_checking}].")

        # Запускаем поток на обработку подключений
        threading.Thread(target=self._accept_connection, daemon=True).start()

    def _accept_connection(self) -> None:
        self._logger.debug(f"Ожидаю подключения на порт [{self._listen_port_connection_checking}].")
        while self._client_state_is_active:
            try:
                client_socket, addr = self._listener_socket.accept()
                self._logger.debug(f'Создаю новую сессию с [{addr}].')
                self._sessions.append(Session(client_socket, addr, self._logger))

            except OSError as e:
                self._logger.debug(f'Завершаю прослушивание порта [{self._listen_port_connection_checking}].')

    def connect(self, interlocutor_ip: str) -> bool:
        self._logger.debug(f'Создаю новую сессию с [{(interlocutor_ip, config.PORT_CLIENT_CONNECTION_CHECKING)}].')
        self._sessions.append(Session(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM),
            (interlocutor_ip, config.PORT_CLIENT_CONNECTION_CHECKING),
            self._logger))
        
        return self._sessions[-1].connect()

    def close(self) -> None:
        self._logger.debug(f"Закрываю прослушивающий сокет нашего клиента на порту [{self._listen_port_connection_checking}].")
        self._client_state_is_active = False
        self._listener_socket.close()

        self._logger.debug("Закрываю все сессии...")
        # Отправить сообщения всем сессиям о закрытии
        for session in self._sessions:
            session.close()
        
        self._logger.debug("Все сессии завершены.")
            