import re
import time
import json
import socket
import queue
import threading
import sqlite3
import requests

import nest_asyncio
nest_asyncio.apply()
import asyncio
from kademlia.network import Server

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


class MessageDataType:
    Text = 'Text'
    File = 'File'


class Event(threading.Event):
    EVENT_CONNECT = 0
    EVENT_DISCONNECT = 1
    EVENT_CLOSE = 2

    EVENT_ADD_RECV_DATA = 3
    EVENT_ADD_SEND_DATA = 4

    EVENT_GET_FILE = 5
    EVENT_FILE_WAS_ACCEPTED = 6

    def __init__(self) -> None:
        super().__init__()
        self.data = queue.Queue()

class DHT_Client:
    def __init__(self) -> None:
        self.loop = asyncio.get_event_loop()
        self.server = Server()
        self.loop.run_until_complete(self._init_server())

    async def _init_server(self):
        await self.server.listen(config.PORT_DHT - 1)
        bootstrap_node = (config.IP_DHT, config.PORT_DHT)
        await self.server.bootstrap([bootstrap_node])

    def set_data(self, key: str, data: dict) -> None:
        self.loop.run_until_complete(self._set_data(key, data))
    
    async def _set_data(self, key: str, data: dict) -> None:
        await self.server.set(key, json.dumps(data))

    def get_data(self, key: str) -> dict:
        return self.loop.run_until_complete(self._get_data(key))
    
    async def _get_data(self, key: str) -> dict:
        data = await self.server.get(key)
        return json.loads(data) if data else None
    
    def stop(self):
        try:
            self.server.stop()
            self.loop.run_until_complete(asyncio.sleep(1))
            self.loop.close()
        except RuntimeError:
            pass

class Session:
    session_counter = 0

    def __init__(self, socket: socket.socket, address: tuple, username: str, logger: Logger, event: Event) -> None:
        self._socket = socket
        self._address = address
        self._our_username = username
        self._interlocutor_username = None
        self._logger = logger
        self._session_is_active = True
        self._last_ping_time = time.time()
        self._event = event

        self._crypto = Encrypter(database_key_path=config.paths['files']['key'])

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
                'username': self._our_username,
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
        self._logger.debug(f"Отправляю Send сообщение клиенту [{self._address}][{self._interlocutor_username}].")

        ciphertext, iv = self._crypto.encrypt(json.dumps(message))

        # Отправляем сообщения
        data_to_send = json.dumps({Message.MESSAGE_SEND_DATA: {
            'data': ciphertext,
            'iv': iv,
            'res_state': is_resended
        }}).encode()
        # Отправляем Send
        self._socket.sendall(len(data_to_send).to_bytes(self._int_size_for_message_len, byteorder='big') + data_to_send)

        self._logger.debug(f"Отправил Send сообщение клиенту [{self._address}][{self._interlocutor_username}] размером [{len(data_to_send)}].")

        if message['type'] == MessageDataType.Text:
            self._temp_buffer_of_our_messages[message['msg_id']] = message
    
    def _load_dialog_history(self) -> None:
        self._logger.debug(f'Подключаюсь к базе данных и загружаю историю диалога с клиентом [{self._address}][{self._interlocutor_username}].')
        
        try:
            table_name = f"table_{self._interlocutor_username}"
            # Подключение к базе данных (или её создание, если она не существует)
            conn = sqlite3.connect(config.paths['files']['history'])
            cur = conn.cursor()

            # Создание таблицы
            req = f'CREATE TABLE IF NOT EXISTS {table_name} (sync_state INTEGER, data BLOB)'
            cur.execute(req)

            # Выполнение запроса на выборку всех записей из таблицы
            req = f"SELECT * FROM {table_name}"
            cur.execute(req)
            
            # Получение всех результатов
            all_rows = cur.fetchall()
            for row in all_rows:
                decoded_row = json.loads(self._crypto.decode_data(row[1]))
                if int(row[0]):
                    self._dialog_history.append(decoded_row)
                else:
                    self._temp_buffer_of_our_messages[decoded_row[0]] = decoded_row

            if self._dialog_history:
                self._dialog_history = sorted(self._dialog_history, key=lambda x: x['time'])

            self._logger.debug(f'Было загружено [{len(self._dialog_history)}] сообщения(-ий) для клиента [{self._address}][{self._interlocutor_username}] из истории.')
            self._logger.debug(f'Было загружено [{len(self._temp_buffer_of_our_messages)}] сообщения(-ий) для клиента [{self._address}][{self._interlocutor_username}], требующих повторной отправки.')

            req = f"DELETE FROM {table_name} WHERE sync_state = ?"
            cur.execute(req, (False,))

            # Сохранение изменений и закрытие соединения с базой данных
            conn.commit()
        except sqlite3.Error as e:
            self._logger.error(f'Не удалось подключиться к базе данных по пути [{config.paths["files"]["history"]}]. Ошибка [{e}].')
        finally:
            if conn:
                conn.close()

    def _save_message_in_db(self, messages: list[dict], is_temp_buffer_elements: bool = False) -> None:
        _messages = []
        for msg in messages:
            _messages.append((not is_temp_buffer_elements, self._crypto.encode_data(json.dumps(msg))))

        try:
            table_name = f"table_{self._interlocutor_username}"
            self._logger.debug(f"Добавляю [{len(_messages)}] сообщение(-ий) в базу данных для клиента [{self._address}][{self._interlocutor_username}].")
            conn = sqlite3.connect(config.paths['files']['history'])
            c = conn.cursor()
             # SQL-запрос для вставки данных
            query = f"INSERT INTO {table_name} (sync_state, data) VALUES (?, ?)"
            
            # Вставляем множество записей
            c.executemany(query, _messages)

             # Сохраняем изменения
            conn.commit()
            self._logger.debug(f"[{len(_messages)}] сообщение(-ий) успешно добавлено(-ы) в базу данных для клиента [{self._address}][{self._interlocutor_username}].")
        except sqlite3.Error as e:
            self._logger.error(f'Ошибка при добавлении данных в БД для клиента [{self._address}][{self._interlocutor_username}]. Ошибка [{e}].')
        finally:
            conn.close()

    def _sync_dialog_history(self, interlocutor_dialog_message_id_list: list) -> None:        
        #ciphertext
        if interlocutor_dialog_message_id_list:
            # Заменяем префиксы, обозначающие, чьи это сообщения (m-наши, o-его)
            for i in range(len(interlocutor_dialog_message_id_list)):
                 interlocutor_dialog_message_id_list[i] = interlocutor_dialog_message_id_list[i].replace('m', 'o') if 'm' in  interlocutor_dialog_message_id_list[i] else interlocutor_dialog_message_id_list[i].replace('o', 'm')
        
        # Если у нас пустая история и у него, то выходим
        if not len(interlocutor_dialog_message_id_list) and not len(self._dialog_history):
            return

        # Проверяем сообщения во временном буфере
        if self._temp_buffer_of_our_messages:
            existed_msg = []
            for msg in self._temp_buffer_of_our_messages.values():
                if msg['msg_id'] not in interlocutor_dialog_message_id_list:
                    self.send({'data': msg, 'type': MessageDataType.Text}, is_resended=True)
                else:
                    # Иначе просто сохраняем сообщения из буфера в историю
                    # Пулим в ивент для обновления истории сообщений
                    self._event.data.put({Event.EVENT_ADD_SEND_DATA: {
                        'addr': self._address,
                        'data': msg,
                        'res_state': True
                    }})
                    existed_msg.append(msg)
                    del self._temp_buffer_of_our_messages[msg['msg_id']]
            
            if existed_msg:                
                self._event.set()
                # Сохраняем сообщение в бд
                self._save_message_in_db(existed_msg)


        # Если у нас не пустая история, то отправляем те сообщения, которых у него нет
        if self._dialog_history:
            for msg in self._dialog_history:
                if msg['msg_id'] not in interlocutor_dialog_message_id_list:
                    self.send({'data': msg, 'type': MessageDataType.Text}, is_resended=True)

        # Если у него тоже не пустая история, то вытягиваем сообщения, которых у нас нет
        if interlocutor_dialog_message_id_list:
            our_msg_id_list = []
            for msg in self._dialog_history:
                our_msg_id_list.append(msg['msg_id'])

            not_existed_msg_id = []
            for msg in interlocutor_dialog_message_id_list:
                if msg not in our_msg_id_list:
                    not_existed_msg_id.append(msg)

            if not_existed_msg_id:
                self._logger.debug(f"Отправляю Sync сообщение клиенту [{self._address}][{self._interlocutor_username}].")

                # Возвращаем префиксы, обозначающие, чьи это сообщения (m-наши, o-его)
                for i in range(len(not_existed_msg_id)):
                    not_existed_msg_id[i] = not_existed_msg_id[i].replace('m', 'o') if 'm' in  not_existed_msg_id[i] else not_existed_msg_id[i].replace('o', 'm')

                ciphertext, iv = self._crypto.encrypt(json.dumps(not_existed_msg_id))

                # Отправляем сообщения
                data_to_send = json.dumps({Message.MESSAGE_SYNC_DATA: {
                    'data': ciphertext,
                    'iv': iv
                }}).encode()
                # Отправляем Send
                self._socket.sendall(len(data_to_send).to_bytes(self._int_size_for_message_len, byteorder='big') + data_to_send)

                self._logger.debug(f"Отправил Sync сообщение клиенту [{self._address}].")
                

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

                    self._interlocutor_username = json_data[Message.MESSAGE_INIT]['username']
                    self._crypto.calculate_dh_secret(json_data[Message.MESSAGE_INIT]['pub_key'])
                    
                    self._load_dialog_history()

                    msg_ids = []
                    for msg in self._dialog_history:
                        msg_ids.append(msg['msg_id'])

                    ciphertext, iv = self._crypto.encrypt(json.dumps(msg_ids))

                    data_to_send = json.dumps({Message.MESSAGE_ACK: {
                        'data': ciphertext,
                        'iv': iv,
                        'username': self._our_username,
                        'pub_key': self._crypto.get_public_key()
                    }}).encode()
                    # Отправляем ответ на Init
                    self._socket.sendall(len(data_to_send).to_bytes(self._int_size_for_message_len, byteorder='big') + data_to_send)
                    self._logger.debug(f"Отправил Ack сообщение клиенту [{self._address}][{self._interlocutor_username}].")

                    self._event.data.put({Event.EVENT_CONNECT: {
                        'username': self._interlocutor_username,
                        'addr': self._address,
                        'session_id': self._session_id,
                        'data': self._dialog_history
                    }})
                    self._event.set()
                    
                
                elif Message.MESSAGE_ACK in json_data:
                    self._last_ping_time = time.time()      # Обновляем время последнего пинга
                    self._logger.debug(f"Получил Ack сообщение от клиента [{self._address}].")
                    
                    self._interlocutor_username = json_data[Message.MESSAGE_ACK]['username']
                    self._crypto.calculate_dh_secret(json_data[Message.MESSAGE_ACK]['pub_key'])

                    ciphertext = json_data[Message.MESSAGE_ACK]['data']
                    iv = json_data[Message.MESSAGE_ACK]['iv']

                    message_data = json.loads(self._crypto.decrypt(ciphertext, iv))

                    self._load_dialog_history()

                    self._event.data.put({Event.EVENT_CONNECT: {
                        'username': self._interlocutor_username,
                        'addr': self._address,
                        'session_id': self._session_id,
                        'data': self._dialog_history
                    }})
                    self._event.set()

                    ping_thread.start()

                    # Синхранизируем данные
                    threading.Thread(target=self._sync_dialog_history, args=(message_data, ), daemon=True).start()


                elif Message.MESSAGE_PING in json_data:
                    self._last_ping_time = time.time()      # Обновляем время последнего пинга
                    self._logger.debug(f"Получил Ping сообщение от клиента [{self._address}][{self._interlocutor_username}].")

                    data_to_send = json.dumps({Message.MESSAGE_PONG: None}).encode()
                    # Отправляем ответ на Ping
                    self._socket.sendall(len(data_to_send).to_bytes(self._int_size_for_message_len, byteorder='big') + data_to_send)

                    self._logger.debug(f"Отправил Pong сообщение клиенту [{self._address}][{self._interlocutor_username}].")

                elif Message.MESSAGE_PONG in json_data:
                    self._last_ping_time = time.time()      # Обновляем время последнего пинга
                    self._logger.debug(f"Получил Pong сообщение от клиента [{self._address}][{self._interlocutor_username}].")

                elif Message.MESSAGE_SEND_DATA in json_data:
                    self._last_ping_time = time.time()      # Обновляем время последнего пинга
                    self._logger.debug(f"Получил Send сообщение от клиента [{self._address}][{self._interlocutor_username}].")
                    
                    ciphertext = json_data[Message.MESSAGE_SEND_DATA]['data']
                    iv = json_data[Message.MESSAGE_SEND_DATA]['iv']

                    message_data = json.loads(self._crypto.decrypt(ciphertext, iv))
                    message_type = message_data['type']
                    message_data = message_data['data']

                    if message_type == MessageDataType.Text:
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
                                'username': self._interlocutor_username,
                                'addr': self._address,
                                'data': message_data,
                                'res_state': is_resended
                            }})
                            self._event.set()

                            # Сохраняем сообщение в бд
                            self._save_message_in_db([message_data])

                        ciphertext, iv = self._crypto.encrypt(json.dumps({'type': MessageDataType.Text, 'data': message_id}))
                        # Отправляем идентификатор сообщения
                        data_to_send = json.dumps({Message.MESSAGE_RECV_DATA: {
                            'data': ciphertext,
                            'iv': iv,
                            'res_state': is_resended
                        }}).encode()

                    elif message_type == MessageDataType.File:
                        # Пулим в ивент для обновления истории сообщений
                        self._event.data.put({Event.EVENT_GET_FILE: {
                            'username': self._interlocutor_username,
                            'addr': self._address,
                            'data': message_data
                        }})
                        self._event.set()

                        ciphertext, iv = self._crypto.encrypt(json.dumps({'type': MessageDataType.File, 'data': message_data['filename']}))
                        # Отправляем идентификатор сообщения
                        data_to_send = json.dumps({Message.MESSAGE_RECV_DATA: {
                            'data': ciphertext,
                            'iv': iv,
                            'res_state': False
                        }}).encode()
                        
                    # Отправляем Recv
                    self._socket.sendall(len(data_to_send).to_bytes(self._int_size_for_message_len, byteorder='big') + data_to_send)

                    self._logger.debug(f"Отправил Recv сообщение клиенту [{self._address}][{self._interlocutor_username}].")

                elif Message.MESSAGE_RECV_DATA in json_data:
                    self._last_ping_time = time.time()      # Обновляем время последнего пинга
                    self._logger.debug(f"Получил Recv сообщение от клиента [{self._address}][{self._interlocutor_username}].")

                    ciphertext = json_data[Message.MESSAGE_RECV_DATA]['data']
                    iv = json_data[Message.MESSAGE_RECV_DATA]['iv']

                    message_data = json.loads(self._crypto.decrypt(ciphertext, iv))

                    if message_data['type'] == MessageDataType.Text:
                        is_resended = json_data[Message.MESSAGE_RECV_DATA]['res_state']
                        if not is_resended:
                            # Пулим в ивент для обновления истории сообщений
                            self._event.data.put({Event.EVENT_ADD_SEND_DATA: {
                                'username': self._interlocutor_username,
                                'addr': self._address,
                                'data': self._temp_buffer_of_our_messages[message_data],
                                'res_state': is_resended
                            }})
                            self._event.set()

                            # Сохраняем сообщение в бд
                            self._save_message_in_db([self._temp_buffer_of_our_messages[message_data]])

                        del self._temp_buffer_of_our_messages[message_data]
                    elif message_data['type'] == MessageDataType.File:
                        # Пулим в ивент для обновления истории сообщений
                        self._event.data.put({Event.EVENT_FILE_WAS_ACCEPTED: {
                            'username': self._interlocutor_username,
                            'addr': self._address,
                            'data': message_data
                        }})
                        self._event.set()
            
                elif Message.MESSAGE_SYNC_DATA in json_data:
                    self._last_ping_time = time.time()      # Обновляем время последнего пинга
                    self._logger.debug(f"Получил Sync сообщение от клиента [{self._address}][{self._interlocutor_username}].")

                    ciphertext = json_data[Message.MESSAGE_SYNC_DATA]['data']
                    iv = json_data[Message.MESSAGE_SYNC_DATA]['iv']

                    message_data = json.loads(self._crypto.decrypt(ciphertext, iv))

                    if not message_data:
                        self._logger.debug(f"Пришел пустой запрос Sync от клиента [{self._address}][{self._interlocutor_username}].")
                        continue

                    self._logger.debug(f"Начинаю отправлять сообщения клиенту [{self._address}][{self._interlocutor_username}]. Всего нужно отправить [{len(message_data)}].")
                    # Переотправляем N месседжей из истории
                    for message in self._dialog_history:
                        if message['msg_id'] in message_data:
                            self.send({'data': message, 'type': MessageDataType.Text}, is_resended=True)

                    self._logger.debug(f"Все [{len(message_data)}] сообщения(-ий) клиенту [{self._address}][{self._interlocutor_username}] были отправлены.")


            except socket.timeout as e:
                self._logger.debug(f"Клиент не отвечает, закрываю соединение с [{self._address}][{self._interlocutor_username}].")
                self.close()

            except json.decoder.JSONDecodeError as e:
                self._logger.error(f'Ошибка при распознании данных. Размер данный [{data_size}]. Данные: [{data}]')
                self._clear_socket_buffer()
                self._logger.debug(f"Отчищаю буфер сокета для [{self._address}][{self._interlocutor_username}].")

            except BrokenPipeError:
                self._logger.debug(f'Клиент [{self._address}][{self._interlocutor_username}] завершил общение. Завершаю сессию.')
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
                self._logger.debug(f"Отправил Ping сообщение клиенту [{self._address}][{self._interlocutor_username}].")
                self._last_ping_time = time.time()      # Обновляем время последнего пинга
            except OSError:
                self._logger.debug(f"Не удалось отправить пинг клиенту [{self._address}][{self._interlocutor_username}].")


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

            if self._interlocutor_username is not None:
                self._event.data.put({Event.EVENT_DISCONNECT: {
                    'username': self._interlocutor_username,
                    'addr': self._address
                }})
                self._event.set()

                self._save_message_in_db(list(self._temp_buffer_of_our_messages.values()), is_temp_buffer_elements=True)

            try:
                self._thread_client_handler.join()
            except RuntimeError:
                pass

            self._logger.debug(f"Сессия для клиента [{self._address}][{self._interlocutor_username}] завершена.")


class Client:
    def __init__(self, logger: Logger, use_local_ip: bool = True, port: int = config.PORT_CLIENT_COMMUNICATION) -> None:
        self._client_state_is_active = True
        self._listen_communication_port = port
        self._logger = logger
        self.event = Event()

        self._use_local_ip = use_local_ip
        self._username = None

        self._logger.debug('Подключаюсь к DHT...')
        self.dht = DHT_Client()

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
                s = Session(client_socket, addr, self._username, self._logger, self.event)
                self._sessions[s.get_id()] = s

            except OSError as e:
                self._logger.debug(f'Завершаю прослушивание порта [{self._listen_communication_port}].')

    def connect(self, interlocutor_ip: str, port: int = config.PORT_CLIENT_COMMUNICATION) -> int:
        self._logger.debug(f'Создаю новую сессию с [{(interlocutor_ip, port)}].')
        s = Session(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM),
            (interlocutor_ip, port),
            self._username,
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
    
    def set_username(self, username: str):
        self._username = username

    def get_ip_address(self) -> str:
        ip_address = None
        
        self._logger.debug("Получаю ip адрес...")
        # Локальный IP
        if self._use_local_ip:
            try:
                # Создаем сокет
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                # Не обязательно устанавливать реальное соединение
                s.connect(("8.8.8.8", 80))
                # Получаем локальный IP-адрес устройства
                ip_address = s.getsockname()[0]
                self._logger.debug(f"Получен локальный ip адрес [{ip_address}].")
            finally:
                # Закрываем сокет
                s.close()
        else:
            try:
                response = requests.get('https://ifconfig.me')
                ip_address = response.text
                self._logger.debug(f"Получен глобальный ip адрес [{ip_address}].")
            except requests.RequestException as e:
                self._logger.error(f"Ошибка при получении глобального IP: {e}.")

        return ip_address
    
    def is_ipv4(self, addr: str) -> bool:
        # Регулярное выражение для проверки IPv4
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(pattern, addr):
            # Проверяем, что каждый октет находится в диапазоне от 0 до 255
            parts = addr.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        return False