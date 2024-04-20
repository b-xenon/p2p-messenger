from logging import Logger
import os
import sqlite3
from typing import Dict, List, Tuple

from config import config
from libs.cryptography import Encrypter
from libs.message import MessageIdType, MessageTextData
from libs.utils import strip_bad_symbols

class DatabaseManager:
    DB_PATH = config.FILES.HISTORY

    def __init__(self, user_id: str, logger: Logger) -> None:
        self._user_id: str = user_id
        self._logger: Logger = logger
        self._database_key: bytes = b''
        
        self._table_name = ''

    def set_table_name(self, user_id: str, peer_id: str):
        """
            Создает шаблоны названий для таблицы базы данных для данного диалога.

        Args:
            user_id (str): Наш id
            peer_id (str): Id собеседника
        """
        self._peer_id = peer_id
        self.table_name_template1 = strip_bad_symbols(f'table_{user_id}_{peer_id}')
        self.table_name_template2 = strip_bad_symbols(f'table_{peer_id}_{user_id}')

        self._database_key = Encrypter.load_database_encode_key(config.PATHS.KEYS, self._user_id, self._peer_id)


    def connect(self):
        """ Устанавливает соединение с базой данных и возвращает объект соединения. """
        return sqlite3.connect(DatabaseManager.DB_PATH)

    def save_data(self, messages: List[MessageTextData], is_outbound_message_buffer: bool = False) -> None:
        """
        Сохраняет данные в указанную таблицу базы данных.

        Args:
            table (List[MessageTextData]): Список сообщений.
            is_outbound_message_buffer (bool): Флаг того, что сохраняются данные их временного буфера.
        """
        if not messages:
            return
        
        _messages = [(not is_outbound_message_buffer, Encrypter.encrypt_for_storage(self._database_key, msg.model_dump_json())) for msg in messages]


        try:
            self._logger.debug(f"Добавляю [{len(_messages)}] сообщение(-ий) в базу данных для клиента [{self._peer_id}].")
            conn = self.connect()
            cursor = conn.cursor()
             # SQL-запрос для вставки данных
            query = f"INSERT INTO {self._table_name} (sync_state, data) VALUES (?, ?)"
            
            # Вставляем множество записей
            cursor.executemany(query, _messages)

             # Сохраняем изменения
            conn.commit()
            self._logger.debug(f"[{len(_messages)}] сообщение(-ий) успешно добавлено(-ы) в базу данных для клиента [{self._peer_id}].")
        except sqlite3.Error as e:
            self._logger.error(f'Ошибка при добавлении данных в БД для клиента [{self._peer_id}]. Ошибка [{e}].')
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
        self._logger.debug(f'Подключаюсь к базе данных и загружаю историю диалога с клиентом [{self._peer_id}].')

        sent_messages: List[MessageTextData] = []
        unsent_messages: Dict[MessageIdType, MessageTextData] = {}
        try:    
            # Подключение к базе данных (или её создание, если она не существует)
            conn = self.connect()
            cursor = conn.cursor()

            req = f"SELECT name FROM sqlite_master WHERE type='table' AND (name='{self.table_name_template1}' OR name='{self.table_name_template2}');"
            cursor.execute(req)
            tables = cursor.fetchall()

            if not tables:
                # Создание таблицы
                req = f'CREATE TABLE {self.table_name_template1} (sync_state INTEGER, data BLOB)'
                cursor.execute(req)
                self._table_name = self.table_name_template1
            else:
                self._table_name = tables[0][0]

            # Выполнение запроса на выборку всех записей из таблицы
            req = f"SELECT * FROM {self._table_name}"
            cursor.execute(req)
            
            # Получение всех результатов
            all_rows = cursor.fetchall()
            
            for row in all_rows:
                decoded_row = MessageTextData.parse_raw((Encrypter.decrypt_from_storage(self._database_key, row[1])))
                sent_messages.append(decoded_row) if int(row[0]) else unsent_messages.update({decoded_row.id: decoded_row})

            if sent_messages:
                sent_messages.sort(key=lambda x: x.id)

            self._logger.debug(f'Было загружено [{len(sent_messages)}] сообщения(-ий) для клиента [{self._peer_id}] из истории.')
            self._logger.debug(f'Было загружено [{len(unsent_messages)}] сообщения(-ий) для клиента [{self._peer_id}], требующих повторной отправки.')

            req = f"DELETE FROM {self._table_name} WHERE sync_state = ?"
            cursor.execute(req, (False,))

            # Сохранение изменений и закрытие соединения с базой данных
            conn.commit()


        except sqlite3.Error as e:
            self._logger.error(f'Не удалось подключиться к базе данных по пути [{DatabaseManager.DB_PATH}]. Ошибка [{e}].')
        finally:
            if conn: # type: ignore
                conn.close()
        return sent_messages, unsent_messages