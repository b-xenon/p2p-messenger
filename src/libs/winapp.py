import tkinter
from tkinter import ttk

import threading

import re
import config
from libs.mylogger import MyLogger, MyLoggerType
from libs.widgets import Chats
from libs.network import Client, Event

class WinApp(tkinter.Tk):
    def __init__(self, use_local_ip: bool = True) -> None:
        super().__init__()
        self._logger = MyLogger('client', MyLoggerType.DEBUG, config.paths["dirs"]["log_client"]).logger

        self._is_close_program_event = False

        self._active_dialogs = {}
        self._inactive_dialogs = {}
        self._our_client = Client(self._logger, use_local_ip=use_local_ip)
        self._ip_address = self._our_client.get_ip_address()

        self.title(f"Client ip[{self._ip_address}]")
        self.geometry('750x700')
        self.minsize(750, 700)

        self._frame_main = ttk.Frame(self)
        self._frame_main.pack(expand=True, fill='both')

        self._frame_connection = ttk.Frame(self._frame_main)
        self._frame_connection.pack()

        self._frame_dht_key = ttk.Frame(self._frame_connection)
        self._frame_dht_key.pack(side='left')

        self.label_our_dht_key = ttk.Label(self._frame_dht_key, text='Ваш DHT ключ:')
        self.label_our_dht_key.pack(padx=5, pady=5)

        self._entry_dht_key_var = tkinter.StringVar()
        self._entry_enter_dht_key = ttk.Entry(self._frame_dht_key, width=30,
                                                   textvariable=self._entry_dht_key_var)
        self._entry_enter_dht_key.pack(padx=10, pady=10)

        self._button_enter_dht_key = ttk.Button(self._frame_dht_key, text='Отправить',
                                                             width=30, command=self._set_dht_data)
        self._button_enter_dht_key.pack(padx=10, pady=10)

        self._frame_connect_to_another_client = ttk.Frame(self._frame_connection)
        self._frame_connect_to_another_client.pack(side='left')

        self.label_another_client_dht_key = ttk.Label(self._frame_connect_to_another_client, text='Чужой DHT ключ:')
        self.label_another_client_dht_key.pack(padx=5, pady=5)

        self._entry_another_client_key_var = tkinter.StringVar()
        self._entry_another_client_key = ttk.Entry(self._frame_connect_to_another_client, width=30,
                                                   textvariable=self._entry_another_client_key_var)
        self._entry_another_client_key.pack(padx=10, pady=10)

        self._button_connect_to_another_client = ttk.Button(self._frame_connect_to_another_client, text='Подключиться',
                                                             width=30, command=self._connect_to_another_client)
        self._button_connect_to_another_client.pack(padx=10, pady=10)

        self._chats = Chats(self._frame_main, self._ip_address, lambda x: self._send_message_to_another_client(x))
        self._chats.pack(expand=True, fill='both', padx=10, pady=10)

        threading.Thread(target=self._handle_dialog, daemon=True).start()

        self.protocol("WM_DELETE_WINDOW", self._prepare_to_close_program)

    def strip_bad_symbols(self, text: str) -> str:
        return re.sub(r"[^\w_.)( -]", "", text)

    def _set_dht_data(self) -> None:
        if not self._entry_dht_key_var.get():
            self._logger.error("Перед отправкой необходимо ввести свой ключ устройства!")
            return
        
        dht_key = self._entry_dht_key_var.get()
        stripped_dht_key = self.strip_bad_symbols(dht_key)

        if dht_key != stripped_dht_key:
            self._logger.error(f"В введенном ключе есть недопустимые символы! Результат проверки [{stripped_dht_key}].")
            return

        self._entry_enter_dht_key.config(state='disabled')
        self._button_enter_dht_key.config(state='disabled')
        self.title(f"Client: ip[{self._ip_address}] | key[{stripped_dht_key}]")
        self._chats.set_username(stripped_dht_key)

        self._logger.debug(f'Добавляю свой ip [{self._ip_address}] в DHT по ключу [{stripped_dht_key}].')
        threading.Thread(target=self._our_client.dht.set_data, args=(stripped_dht_key, {'ip': self._ip_address}), daemon=True).start()
        self._our_client.set_username(stripped_dht_key)

    def _handle_dialog(self):
        while self._our_client.get_state():
            self._our_client.event.wait()
            self._our_client.event.clear()

            while not self._our_client.event.data.empty():
                event_data = self._our_client.event.data.get(block=False)
                if not event_data:
                    break
                
                try:
                    def show_message(msg, username):
                        dialog = self._chats.get_dialog(self._active_dialogs[username]['dialog_id'])
                        exist = dialog.exist_message(msg)
                        if not exist:
                            dialog.recieve_message(msg)


                    if Event.EVENT_CONNECT in event_data:
                        event_data = event_data[Event.EVENT_CONNECT] 
                        interlocutor_ip = event_data['addr'][0]
                        data = event_data['data']
                        interlocutor_username = event_data['username']

                        if interlocutor_ip in self._inactive_dialogs:
                            self._chats.load_dialog(self._inactive_dialogs[interlocutor_username])
                            
                            self._active_dialogs[interlocutor_username] = {}
                            self._active_dialogs[interlocutor_username]['session_id'] = event_data['session_id']
                            self._active_dialogs[interlocutor_username]['dialog_id'] = self._inactive_dialogs[interlocutor_username]
                            
                            del self._inactive_dialogs[interlocutor_username]
                        else:
                            self._active_dialogs[interlocutor_username] = {}
                            self._active_dialogs[interlocutor_username]['session_id'] = event_data['session_id']
                            self._active_dialogs[interlocutor_username]['dialog_id'] = self._chats.add_dialog(interlocutor_username, interlocutor_username, data)

                    elif Event.EVENT_DISCONNECT in event_data:
                        event_data = event_data[Event.EVENT_DISCONNECT] 
                        interlocutor_ip = event_data['addr'][0]
                        interlocutor_username = event_data['username']

                        # self._chats.hide_dialog(self._active_dialogs[event_data[Event.EVENT_CONNECT][0]])
                        if interlocutor_username in self._active_dialogs:
                            self._chats.inactivate_dialog(self._active_dialogs[interlocutor_username]['dialog_id'])
                            self._inactive_dialogs[interlocutor_username] = self._active_dialogs[interlocutor_username]['dialog_id']
                            del self._active_dialogs[interlocutor_username]

                    elif Event.EVENT_ADD_RECV_DATA in event_data:
                        event_data = event_data[Event.EVENT_ADD_RECV_DATA] 
                        interlocutor_ip = event_data['addr'][0]
                        interlocutor_username = event_data['username']

                        if interlocutor_username in self._active_dialogs:
                            threading.Thread(target=show_message, args=(event_data['data'], interlocutor_username), daemon=True).start()

                    elif Event.EVENT_ADD_SEND_DATA in event_data:
                        event_data = event_data[Event.EVENT_ADD_SEND_DATA] 
                        interlocutor_ip = event_data['addr'][0]
                        is_resended = event_data['res_state']
                        interlocutor_username = event_data['username']

                        if is_resended:
                            if interlocutor_username in self._active_dialogs:
                                threading.Thread(target=show_message, args=(event_data['data'], interlocutor_username), daemon=True).start()

                    elif Event.EVENT_CLOSE in event_data:
                        return
                except KeyError as e:
                    self._logger.error(f"Ошибка с доступом по ключу [{e}].")

    def _connect_to_another_client(self):
        if not self._entry_dht_key_var.get():
            self._logger.error("Перед подключением необходимо ввести свой ключ устройства!")
            return

        another_client = self._entry_another_client_var.get() 
        if not another_client:
            self._logger.error("Перед подключением необходимо ввести ключ другого устройства!")
            return
        
        threading.Thread(target=self._connect_to_another_client_with_dht, args=(another_client, ), daemon=True).start()

    def _connect_to_another_client_with_dht(self, another_client):
        try:
            another_client_ip = self._dht.get_data(another_client)['ip']
        except (OSError, TypeError, KeyError) as e:
            self._logger.error(f'Не удалось получить ip клиента [{another_client}]. Ошибка [{e}].')
            return

        if not self._our_client.is_ipv4(another_client_ip):
            self._logger.error(f"Введен некорректный ip-адрес [{another_client_ip}]!"
                               f" Ip-адрес должен быть в формате IPv4!")
            return
        
        if another_client_ip == self._ip_address:
            self._logger.error(f"Пока нельзя подключаться самому к себе!")
            return

        if another_client in self._active_dialogs:
            self._logger.debug(f"Диалог с клиентом {another_client} уже открыт.")
            return
        
        # установаем соединение
        threading.Thread(target=self._our_client.connect, args=(another_client_ip, ), daemon=True).start()

    
    def _send_message_to_another_client(self, message: dict):
        self._our_client.get_session(
            self._active_dialogs[self._chats.get_current_dialog().get_interlocutor_id()]['session_id']
        ).send(message)


    def _prepare_to_close_program(self) -> None:
        
        def __close_program():
            self._logger.debug("Завершаю программу...")
            self._our_client.dht.stop()
            self._our_client.close()
            self.destroy()

        
        if not self._is_close_program_event:
            self._is_close_program_event = True
            threading.Thread(target=__close_program, daemon=True).start()

    def close(self):
        self._prepare_to_close_program()

    def run(self) -> None:
        self.mainloop()