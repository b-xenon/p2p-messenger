import time
import json
import socket
import queue
import threading
import sqlite3

from libs.cryptography import Encrypter
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

        self._crypto = Encrypter()

        self._session_id = Session.session_counter
        Session.session_counter += 1

        self._dialog_history = []
        self._temp_buffer_of_our_messages = {}

        self._int_size_for_message_len = 4

        self._load_dialog_history()

        self._thread_client_handler = threading.Thread(target=self._handle_client, daemon=True)
        self._thread_client_handler.start()

    def get_id(self) -> int:
        return self._session_id

    def connect(self) -> int:
        try:
            self._logger.debug(f"Устанавливаю соединение с клиентом [{self._address}].")
            
            self._socket.connect(self._address)

            data_to_send = json.dumps({Message.MESSAGE_INIT: {
                'dialog_len': len(self._dialog_history),
                'last_msg_id': self._dialog_history[-1]['msg_id'] if self._dialog_history else None,
                'pub_key': self._crypto.get_public_key()
                
            }}).encode()
            # Отправляем Init
            self._socket.sendall(len(data_to_send).to_bytes(self._int_size_for_message_len, byteorder='big') + data_to_send)

            self._logger.debug(f"Отправил Init сообщение клиенту [{self._address}].")
            return self._session_id
        
        except OSError:
            self._logger.debug(f'Произошло закрытие сокета. Завершаю сессию.')
            return -1

    def send(self, message: dict, is_resended: bool = False) -> None:
        self._logger.debug(f"Отправляю Send сообщение клиенту [{self._address}].")

        ciphertext, iv = self._crypto.encrypt(json.dumps(message).encode())

        # Отправляем сообщения
        data_to_send = json.dumps({Message.MESSAGE_SEND_DATA: {
            'data': ciphertext,
            'iv': iv,
            'res_state': is_resended
        }}).encode()
        # Отправляем Send
        self._socket.sendall(len(data_to_send).to_bytes(self._int_size_for_message_len, byteorder='big') + data_to_send)

        self._logger.debug(f"Отправил Send сообщение клиенту [{self._address}] размером [{len(data_to_send)}].")

        self._temp_buffer_of_our_messages[message['msg_id']] = message
    
    def _load_dialog_history(self) -> None:
        self._logger.debug(f'Подключаюсь к базе данных и загружаю историю диалога с клиентом [{self._address}].')
        
        try:
            table_name = f"table_{self._address[0].replace('.', '_').strip()}"
            # Подключение к базе данных (или её создание, если она не существует)
            conn = sqlite3.connect(config.paths['files']['db'])
            cur = conn.cursor()

            # Создание таблицы
            req = f'CREATE TABLE IF NOT EXISTS {table_name} (sync_state INTEGER, id TEXT, author TEXT, message TEXT, time TEXT)'
            cur.execute(req)

            # Выполнение запроса на выборку всех записей из таблицы
            req = f"SELECT * FROM {table_name}"
            cur.execute(req)
            
            # Получение всех результатов
            all_rows = cur.fetchall()
            for row in all_rows:
                message = {
                        'author': row[2],
                        'msg': row[3],
                        'msg_id': row[1],
                        'time': row[4]
                    }
                if int(row[0]):
                    self._dialog_history.append(message)
                else:
                    self._temp_buffer_of_our_messages[row[1]] = message

            if self._dialog_history:
                self._dialog_history = sorted(self._dialog_history, key=lambda x: x['time'])

            self._logger.debug(f'Было загружено [{len(self._dialog_history)}] сообщения(-ий) для клиента [{self._address}] из истории.')
            self._logger.debug(f'Было загружено [{len(self._temp_buffer_of_our_messages)}] сообщения(-ий) для клиента [{self._address}], требующих повторной отправки.')

            req = f"DELETE FROM {table_name} WHERE sync_state = ?"
            cur.execute(req, (False,))

            # Сохранение изменений и закрытие соединения с базой данных
            conn.commit()
        except sqlite3.Error as e:
            self._logger.error(f'Не удалось подключиться к базе данных по пути [{config.paths["files"]["db"]}]. Ошибка [{e}].')
        finally:
            if conn:
                conn.close()

    def _save_message_in_db(self, messages: list[dict], is_temp_buffer_elements: bool = False) -> None:
        _messages = []
        for msg in messages:
            _messages.append((not is_temp_buffer_elements, msg['msg_id'], msg['author'], msg['msg'], msg['time']))
        
        if not is_temp_buffer_elements:
            self._dialog_history += messages

        try:
            table_name = f"table_{self._address[0].replace('.', '_').strip()}"
            self._logger.debug(f"Добавляю [{len(_messages)}] сообщение(-ий) в базу данных для клиента [{self._address}].")
            conn = sqlite3.connect(config.paths['files']['db'])
            c = conn.cursor()
             # SQL-запрос для вставки данных
            query = f"INSERT INTO {table_name} (sync_state, id, author, message, time) VALUES (?, ?, ?, ?, ?)"
            
            # Вставляем множество записей
            c.executemany(query, _messages)

             # Сохраняем изменения
            conn.commit()
            self._logger.debug(f"[{len(_messages)}] сообщение(-ий) успешно добавлено(-ы) в базу данных для клиента [{self._address}].")
        except sqlite3.Error as e:
            self._logger.error(f'Ошибка при добавлении данных в БД для клиента [{self._address}]. Ошибка [{e}].')
        finally:
            conn.close()

    def _sync_dialog_history(self, interlocutor_dialog_len: int, interlocutor_last_message_id: str) -> None:
        if interlocutor_last_message_id:
            # Заменяем префиксы, обозначающие, чьи это сообщения (m-наши, o-его)
            interlocutor_last_message_id = interlocutor_last_message_id.replace('m', 'o') if 'm' in interlocutor_last_message_id else interlocutor_last_message_id.replace('o', 'm')
        
        if interlocutor_dialog_len == len(self._dialog_history):
            # Если у нас и у него не пустые истории
            if len(self._dialog_history):                
                # размеры историй одинаковы, но не нулевые, поэтому проверяем id последних сообщений
                if interlocutor_last_message_id:
                    # Если индексы не совпали, то нужно переоправить последние сообщения
                    if self._dialog_history[-1]['msg_id'] != interlocutor_last_message_id:
                        # Проверяем, сохранились ли данные меседжи в временном буфере
                        if not self._temp_buffer_of_our_messages and interlocutor_last_message_id not in self._temp_buffer_of_our_messages:
                            # Если нет, то отправляем последние сообщения, как новые
                            self.send(self._dialog_history[-1], is_resended=True)
                            return
                        
                        # Иначе просто сохраняем сообщения из буфера в историю
                        
                        # Пулим в ивент для обновления истории сообщений
                        self._event.data.put({Event.EVENT_ADD_SEND_DATA: {
                            'addr': self._address,
                            'data': self._temp_buffer_of_our_messages[interlocutor_last_message_id],
                            'res_state': True
                        }})
                        self._event.set()

                        # Сохраняем сообщение в бд
                        self._save_message_in_db([self._temp_buffer_of_our_messages[interlocutor_last_message_id]])

                        del self._temp_buffer_of_our_messages[interlocutor_last_message_id]

                    
            # Проверяем, нужно ли переотправить сообщение
            if not self._temp_buffer_of_our_messages:
                return
            # Переотправляем все месседжи во временном буфере
            for message in self._temp_buffer_of_our_messages.values():
                self.send(message, is_resended=True)
        
        # Для разных размеров историй
        else:
            delta_dialog_len = len(self._dialog_history) - interlocutor_dialog_len

            def _send_sync(messages_num):
                self._logger.debug(f"Отправляю Sync сообщение клиенту [{self._address}].")

                ciphertext, iv = self._crypto.encrypt(str(messages_num).encode())

                # Отправляем сообщения
                data_to_send = json.dumps({Message.MESSAGE_SYNC_DATA: {
                    'data': ciphertext,
                    'iv': iv
                }}).encode()
                # Отправляем Send
                self._socket.sendall(len(data_to_send).to_bytes(self._int_size_for_message_len, byteorder='big') + data_to_send)

                self._logger.debug(f"Отправил Sync сообщение клиенту [{self._address}].")
                
            # Если у нас меньше (мы отправляли - он принимал)
            if delta_dialog_len < 0:
                # Проверяем наш буфер
                if not self._temp_buffer_of_our_messages:
                    # То отправляем ему сообщение о вытягивании данных
                    _send_sync(abs(delta_dialog_len))
                    return

                # Иначе пишем данные из буфера в историю
                messages = []
                buf = self._temp_buffer_of_our_messages.values()
                size = min(abs(delta_dialog_len), len(self._temp_buffer_of_our_messages))
                for i in range(size):
                    # Пулим в ивент для обновления истории сообщений
                    self._event.data.put({Event.EVENT_ADD_SEND_DATA: {
                        'addr': self._address,
                        'data': buf[i],
                        'res_state': True
                    }})
                    messages.append(buf[i])
                self._event.set()

                # Сохраняем сообщение в бд
                self._save_message_in_db(messages)

                for msg in messages:
                    del self._temp_buffer_of_our_messages[msg['msg_id']]

                # Проверяем осталась ли разница в историях
                if len(self._dialog_history) < interlocutor_dialog_len:
                    # То отправляем ему сообщение о вытягивании данных
                    _send_sync(abs(len(self._dialog_history) - interlocutor_dialog_len))
                
                # Если остались данные в буфере, то отправляем их ему
                if self._temp_buffer_of_our_messages:
                    # Переотправляем все месседжи во временном буфере
                    for message in self._temp_buffer_of_our_messages.values():
                        self.send(message, is_resended=True)

            # Если у нас больше (мы принимали - он отправлял)
            elif delta_dialog_len > 0:
                pass

    def _handle_client(self) -> None:
        # Использование метода settimeout(ping_timeout) для сокета client_socket в контексте 
        # TCP-соединений устанавливает таймаут на блокирующие операции сокета, такие как recv() и send().
        # Это значит, что операция будет ждать данных или возможности отправки данных в течение указанного времени
        # (ping_timeout), и если за это время не произойдет никаких действий, то операция завершится с исключением socket.timeout.
        
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

                    self._crypto.calculate_dh_secret(json_data[Message.MESSAGE_INIT]['pub_key'])

                    data_to_send = json.dumps({Message.MESSAGE_ACK: {
                        'dialog_len': len(self._dialog_history),
                        'last_msg_id': self._dialog_history[-1]['msg_id'] if self._dialog_history else None,
                        'pub_key': self._crypto.get_public_key()
                    }}).encode()
                    # Отправляем ответ на Init
                    self._socket.sendall(len(data_to_send).to_bytes(self._int_size_for_message_len, byteorder='big') + data_to_send)

                    self._event.data.put({Event.EVENT_CONNECT: {
                        'addr': self._address,
                        'session_id': self._session_id,
                        'data': self._dialog_history
                    }})
                    self._event.set()

                    self._logger.debug(f"Отправил Ack сообщение клиенту [{self._address}].")

                    # Синхранизируем данные
                    interlocutor_dialog_len = json_data[Message.MESSAGE_INIT]['dialog_len']
                    threading.Thread(target=self._sync_dialog_history, args=(
                        interlocutor_dialog_len,
                        json_data[Message.MESSAGE_INIT]['last_msg_id']),
                        daemon=True).start()
                    
                
                elif Message.MESSAGE_ACK in json_data:
                    self._last_ping_time = time.time()      # Обновляем время последнего пинга
                    self._logger.debug(f"Получил Ack сообщение от клиента [{self._address}].")
                    
                    self._crypto.calculate_dh_secret(json_data[Message.MESSAGE_ACK]['pub_key'])

                    self._event.data.put({Event.EVENT_CONNECT: {
                        'addr': self._address,
                        'session_id': self._session_id,
                        'data': self._dialog_history
                    }})
                    self._event.set()

                    ping_thread.start()

                    # Синхранизируем данные
                    interlocutor_dialog_len = json_data[Message.MESSAGE_ACK]['dialog_len']
                    threading.Thread(target=self._sync_dialog_history, args=(
                        interlocutor_dialog_len,
                        json_data[Message.MESSAGE_ACK]['last_msg_id']),
                        daemon=True).start()


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
                    
                    ciphertext = json_data[Message.MESSAGE_SEND_DATA]['data']
                    iv = json_data[Message.MESSAGE_SEND_DATA]['iv']

                    message_data = json.loads(self._crypto.decrypt(ciphertext, iv))

                    message_id = message_data['msg_id']
                    is_resended = json_data[Message.MESSAGE_SEND_DATA]['res_state']

                    message_data['msg_id'] = message_id.replace('m', 'o') if 'm' in message_id else message_id.replace('o', 'm')
                    new_message_id = message_data['msg_id']

                    already_exist = False
                    if is_resended:
                        for msg in self._dialog_history:
                            if new_message_id == msg['msg_id']:
                                already_exist = True
                                break
                    
                    if not already_exist:
                        # Пулим в ивент для обновления истории сообщений
                        self._event.data.put({Event.EVENT_ADD_RECV_DATA: {
                            'addr': self._address,
                            'data': message_data,
                            'res_state': is_resended
                        }})
                        self._event.set()

                        # Сохраняем сообщение в бд
                        self._save_message_in_db([message_data])

                    ciphertext, iv = self._crypto.encrypt(message_id.encode())
                    # Отправляем идентификатор сообщения
                    data_to_send = json.dumps({Message.MESSAGE_RECV_DATA: {
                        'data': ciphertext,
                        'iv': iv,
                        'res_state': is_resended
                    }}).encode()
                    # Отправляем Recv
                    self._socket.sendall(len(data_to_send).to_bytes(self._int_size_for_message_len, byteorder='big') + data_to_send)

                    self._logger.debug(f"Отправил Recv сообщение клиенту [{self._address}].")

                elif Message.MESSAGE_RECV_DATA in json_data:
                    self._last_ping_time = time.time()      # Обновляем время последнего пинга
                    self._logger.debug(f"Получил Recv сообщение от клиента [{self._address}].")

                    ciphertext = json_data[Message.MESSAGE_RECV_DATA]['data']
                    iv = json_data[Message.MESSAGE_RECV_DATA]['iv']

                    message_data = self._crypto.decrypt(ciphertext, iv)

                    is_resended = json_data[Message.MESSAGE_RECV_DATA]['res_state']

                    if not is_resended:
                        # Пулим в ивент для обновления истории сообщений
                        self._event.data.put({Event.EVENT_ADD_SEND_DATA: {
                            'addr': self._address,
                            'data': self._temp_buffer_of_our_messages[message_data],
                            'res_state': is_resended
                        }})
                        self._event.set()

                        # Сохраняем сообщение в бд
                        self._save_message_in_db([self._temp_buffer_of_our_messages[message_data]])

                    del self._temp_buffer_of_our_messages[message_data]

            
                elif Message.MESSAGE_SYNC_DATA in json_data:
                    self._last_ping_time = time.time()      # Обновляем время последнего пинга
                    self._logger.debug(f"Получил Sync сообщение от клиента [{self._address}].")

                    ciphertext = json_data[Message.MESSAGE_SYNC_DATA]['data']
                    iv = json_data[Message.MESSAGE_SYNC_DATA]['iv']

                    message_data = int(self._crypto.decrypt(ciphertext, iv))

                    self._logger.debug(f"Начинаю отправлять последние [{message_data}] сообщений клиенту [{self._address}].")
                    # Переотправляем N месседжей из истории
                    messages = self._dialog_history[-message_data:]
                    for message in messages:
                        self.send(message, is_resended=True)

                    self._logger.debug(f"Последние [{message_data}] сообщений клиенту [{self._address}] были отправлены.")


            except socket.timeout as e:
                self._logger.debug(f"Клиент не отвечает, закрываю соединение с [{self._address}].")
                self.close()

            except json.decoder.JSONDecodeError as e:
                self._logger.error(f'Ошибка при распознании данных. Размер данный [{data_size}]. Данные: [{data}]')
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
                self._last_ping_time = time.time()      # Обновляем время последнего пинга
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
        if self._session_is_active:
            self._session_is_active = False
            self._socket.close()

            self._event.data.put({Event.EVENT_DISCONNECT: self._address})
            self._event.set()

            self._save_message_in_db(list(self._temp_buffer_of_our_messages.values()), is_temp_buffer_elements=True)

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