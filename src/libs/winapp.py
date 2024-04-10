import base64
import tkinter
from tkinterdnd2 import TkinterDnD
from tkinter import ttk

import threading

import os
import re
import json
import config
from libs.mylogger import MyLogger, MyLoggerType
from libs.widgets import Chats, CustomMessageBox, CustomMessageType
from libs.network import Client, Event, MessageDataType

class WinApp(TkinterDnD.Tk):
    def __init__(self, use_local_ip: bool = True) -> None:
        super().__init__()
        self._default_init()
        self._logger = MyLogger('client', MyLoggerType.DEBUG, config.paths["dirs"]["log_client"]).logger

        self._is_close_program_event = False

        self._active_dialogs = {}
        self._inactive_dialogs = {}
        self._unavaliable_dht_keys = ['None']
        self._our_client = Client(self._logger, use_local_ip=use_local_ip)
        self._ip_address = self._our_client.get_ip_address()

        self._style = None
        self._style_is_dark_theme = True
        self._style_theme_path = config.paths['dirs']['theme']
        self._style_theme_dark_was_loaded = False
        self._style_theme_light_was_loaded = False
        self._style_theme_file_dark = config.paths['files']['theme']['dark']
        self._style_theme_file_light = config.paths['files']['theme']['light']
        self._style_theme_file = self._style_theme_file_dark if self._style_is_dark_theme else self._style_theme_file_light

        self._style_is_default_theme = False

        self._loads_from_config()
        self._create_window()

        threading.Thread(target=self._handle_dialog, daemon=True).start()
        self.protocol("WM_DELETE_WINDOW", self._prepare_to_close_program)

    def _create_window(self):
        self.title(f"Client ip[{self._ip_address}]")
        self.geometry('750x730')
        self.minsize(750, 730)

        try:
            self.iconbitmap(config.paths['files']['icon']['main'])
        except tkinter.TclError:
            pass
        self._load_theme_styles()

        self._frame_main = ttk.Frame(self)
        self._frame_main.pack(expand=True, fill='both')

        self._menu_main = tkinter.Menu(self._frame_main, tearoff=0)

        def _set_logger_level(*args):
            self._logger.setLevel(MyLoggerType.DEBUG) if self._is_logger_mode_debug_var.get() else self._logger.setLevel(MyLoggerType.ERROR)

        self._menu_additional = tkinter.Menu(self._menu_main, tearoff=0)
        self._is_logger_mode_debug_var = tkinter.BooleanVar(value=self._is_logger_mode_debug)
        self._is_logger_mode_debug_var.trace_add('write', _set_logger_level)

        self._menu_additional.add_checkbutton(label='Логгер в режиме дебага', onvalue=1, offvalue=0,
                                         variable=self._is_logger_mode_debug_var)

        self._menu_themes = tkinter.Menu(self._menu_additional, tearoff=0)

        def _change_to_default(*args):
            self._set_default_theme(menu=self._menu_themes)
        
        self._default_theme_var = tkinter.BooleanVar(value=self._style_is_default_theme)
        self._default_theme_var.trace_add('write', _change_to_default)

        self._menu_themes.add_checkbutton(label='Простая тема', onvalue=1, offvalue=0, variable=self._default_theme_var)

        if self._style_theme_dark_was_loaded and self._style_theme_light_was_loaded:
            self._theme_was_changed = tkinter.BooleanVar()
            self._is_dark_theme = tkinter.BooleanVar(value=self._style_is_dark_theme)
            self._is_dark_theme.trace_add('write', self._change_theme)

            self._menu_themes.add_checkbutton(label='Тёмная тема', onvalue=1, offvalue=0, variable=self._is_dark_theme)
            if self._style_is_default_theme:
                self._menu_themes.entryconfigure('Тёмная тема', state='disabled')
        else:
            self._menu_themes.entryconfig('Простая тема', state='disable')

        self._menu_additional.add_cascade(label='Темы', menu=self._menu_themes)
        self._menu_main.add_cascade(label='Дополнительно', menu=self._menu_additional)

        _separator1 = ttk.Separator(self._frame_main)
        _separator1.pack(pady=5, fill=tkinter.X)

        _menu_button = ttk.Menubutton(self._frame_main, text='Меню', menu=self._menu_main, direction="below")
        _menu_button.pack()

        _separator2 = ttk.Separator(self._frame_main)
        _separator2.pack(pady=5, fill=tkinter.X)

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

        self._button_connect_to_another_client = ttk.Button(self._frame_connect_to_another_client, text='Подключиться/Отключиться',
                                                             width=30, command=self._connect_to_another_client)
        self._button_connect_to_another_client.pack(padx=10, pady=10)

        self._chats = Chats(self._frame_main, self._ip_address, lambda x: self._send_message_to_another_client(x))
        self._chats.pack(expand=True, fill='both', padx=10, pady=10)

    def _default_init(self) -> None:
        self._style_is_dark_theme = True
        self._style_is_default_theme = False
        self._is_logger_mode_debug = config.LOGGER_DEBUG_MODE

    def _loads_from_config(self) -> None:
        # Начальная инициализация основных полей
        config_filename = config.paths['files']['config']

        # Если существует файл конфигурации, то загружаемся с него
        if os.path.exists(config_filename) and os.path.isfile(config_filename):
            try:
                with open(config_filename, 'r', encoding='utf-8') as config_file:
                    try:
                        data = json.load(config_file)
                        self._style_is_default_theme = data['default_theme']
                        self._logger.debug(f'Значение стандартной темы установлено в: [{self._style_is_default_theme}]')
                        self._style_is_dark_theme = data['dark_theme']
                        self._logger.debug(f'Значение темной темы установлено в: [{self._style_is_dark_theme}]')
                        self._is_logger_mode_debug = data['logger_mode_debug']
                        self._logger.debug(f'Значение логгера установлено в: [{self._is_logger_mode_debug}]')

                    except json.decoder.JSONDecodeError:
                        self._logger.error(f'Ошибка при разборе файла [{config_filename}]!')
                        self._default_init()
                    except KeyError:
                        self._logger.error(f'Ошибка при попытке извлечь данные. '
                                     f'Видимо файл [{config_filename}] был ошибочно записан, либо некорректно изменён!')
                        self._default_init()
            except IOError:
                self._logger.error(f'Не удалось открыть файл [{config_filename}] для чтения!')
                self._default_init()

    def _set_default_theme(self, menu):
        """
        Устанавливаем простую тему вместо темной/белой

        :param menu: вкладка меню, к которой прикреплен чекбокс (для замены значения в нем)
        :return:
        """

        self._style_is_default_theme = not self._style_is_default_theme

        if self._style_is_default_theme is True:
            self._style.theme_use(config.DEFAULT_THEME)

            # Отключаем переключатель у темной/светлой
            if self._style_theme_dark_was_loaded and self._style_theme_light_was_loaded:
                menu.entryconfigure('Тёмная тема', state='disabled')
        else:
            if self._style_theme_dark_was_loaded and self._style_theme_light_was_loaded:
                menu.entryconfigure('Тёмная тема', state='active')
                self._style_theme_file = self._style_theme_file_dark if self._style_is_dark_theme else self._style_theme_file_light
                self._style.theme_use(self._style_theme_file)

                self._theme_was_changed.set(self._style_is_dark_theme)

    def _load_theme_styles(self):
        if os.path.exists(f'{self._style_theme_path}{self._style_theme_file}.tcl'):
            try:
                self.tk.call("source", f'{self._style_theme_path}{self._style_theme_file_dark}.tcl')
                self._style_theme_dark_was_loaded = True
            except tkinter.TclError:
                self._logger.error(f'Ошибка при открытии файла [{self._style_theme_path}{self._style_theme_file_dark}.tcl]!')
            try:
                self.tk.call("source", f'{self._style_theme_path}{self._style_theme_file_light}.tcl')
                self._style_theme_light_was_loaded = True
            except tkinter.TclError:
                self._.error(f'Ошибка при открытии файла [{self._style_theme_path}{self._style_theme_file_light}.tcl]!')
            try:
                self._style = ttk.Style(self)
                self._style_theme_file = self._style_theme_file_dark if self._style_is_dark_theme else self._style_theme_file_light
                self._style.theme_use(self._style_theme_file if not self._style_is_default_theme else config.DEFAULT_THEME)
            except tkinter.TclError:
                self._.error(f'Не удалось установить стиль [{self._style_theme_file}]!')
        else:
            self._style = ttk.Style(self)
            self._style.theme_use(config.DEFAULT_THEME)

    def _change_theme(self, *args):
        """
        Меняем тему для текущего окна

        :param args:
        :return:
        """

        if self._style_theme_dark_was_loaded and self._style_theme_light_was_loaded:
            self._style_is_dark_theme = not self._style_is_dark_theme
            self._style_theme_file = self._style_theme_file_dark if self._style_is_dark_theme else self._style_theme_file_light
            self._style.theme_use(self._style_theme_file)

            self._theme_was_changed.set(self._style_is_dark_theme)


    def _strip_bad_symbols(self, text: str) -> str:
        return re.sub(r"[^\w_.)( -]", "", text)

    def _set_dht_data(self) -> None:
        if not self._entry_dht_key_var.get():
            self._logger.error("Перед отправкой необходимо ввести свой ключ устройства!")
            CustomMessageBox.show(self, 'Ошибка', "Перед отправкой необходимо ввести свой ключ устройства!", CustomMessageType.ERROR)
            return
        
        dht_key = self._entry_dht_key_var.get()
        stripped_dht_key = self._strip_bad_symbols(dht_key)

        if dht_key != stripped_dht_key:
            self._logger.error(f"В введенном ключе есть недопустимые символы! Результат проверки [{stripped_dht_key}].")
            CustomMessageBox.show(self, 'Ошибка', f"В введенном ключе есть недопустимые символы! Результат проверки [{stripped_dht_key}].", CustomMessageType.ERROR)
            return

        if not self._check_is_avaliable_username(stripped_dht_key):
            self._logger.error(f"Введенный ключ входит в число недопустимых! Недопустимые ключи [{self._unavaliable_dht_keys}].")
            CustomMessageBox.show(self, 'Ошибка', f"Введенный ключ входит в число недопустимых! Недопустимые ключи [{self._unavaliable_dht_keys}].", CustomMessageType.ERROR)
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

                        if interlocutor_username in self._inactive_dialogs:
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
                        interlocutor_username = event_data['username']

                        if interlocutor_username in self._active_dialogs:
                            threading.Thread(target=show_message, args=(event_data['data'], interlocutor_username), daemon=True).start()

                    elif Event.EVENT_ADD_SEND_DATA in event_data:
                        event_data = event_data[Event.EVENT_ADD_SEND_DATA] 
                        is_resended = event_data['res_state']
                        interlocutor_username = event_data['username']

                        if is_resended:
                            if interlocutor_username in self._active_dialogs:
                                threading.Thread(target=show_message, args=(event_data['data'], interlocutor_username), daemon=True).start()

                    elif Event.EVENT_GET_FILE in event_data:
                        event_data = event_data[Event.EVENT_GET_FILE]
                        interlocutor_username = event_data['username']

                        # Пишем файл
                        threading.Thread(target=self._create_file_from_data, args=(event_data['data'], interlocutor_username), daemon=True).start()

                    elif Event.EVENT_FILE_WAS_ACCEPTED in event_data:
                        event_data = event_data[Event.EVENT_FILE_WAS_ACCEPTED]
                        interlocutor_username = event_data['username']
                        CustomMessageBox.show(self, 'Инфо', f'Файл [{event_data["data"]}] успешно доставлен до адрессата [{interlocutor_username}].', CustomMessageType.SUCCESS)

                    elif Event.EVENT_CLOSE in event_data:
                        return
                except KeyError as e:
                    self._logger.error(f"Ошибка с доступом по ключу [{e}].")

    def _check_is_avaliable_username(self, username: str) -> bool:
        if username in self._unavaliable_dht_keys:
            return False
        return True

    def _connect_to_another_client(self):
        if not self._entry_dht_key_var.get() or self._button_enter_dht_key['state'] == tkinter.NORMAL:
            self._logger.error("Перед подключением необходимо ввести свой ключ устройства!")
            CustomMessageBox.show(self, 'Ошибка', "Перед подключением необходимо ввести свой ключ устройства!", CustomMessageType.ERROR)
            return

        another_client = self._entry_another_client_key_var.get() 
        if not another_client:
            self._logger.error("Перед подключением необходимо ввести ключ другого устройства!")
            CustomMessageBox.show(self, 'Ошибка', "Перед подключением необходимо ввести ключ другого устройства!", CustomMessageType.ERROR)
            return
        
        if not self._check_is_avaliable_username(another_client):
            self._logger.error(f"Введенный ключ входит в число недопустимых! Недопустимые ключи [{self._unavaliable_dht_keys}].")
            CustomMessageBox.show(self, 'Ошибка', f"Введенный ключ входит в число недопустимых! Недопустимые ключи [{self._unavaliable_dht_keys}].", CustomMessageType.ERROR)
            return
        
        threading.Thread(target=self._connect_or_disconect, args=(another_client, ), daemon=True).start()

    def _connect_or_disconect(self, another_client):
        if another_client in self._active_dialogs:
            self._logger.debug(f"Отключаюсь от {another_client}.")
            self._our_client.get_session(self._active_dialogs[another_client]['session_id']).close()
            CustomMessageBox.show(self, 'Инфо', f'Общение с [{another_client}] завершено!', CustomMessageType.SUCCESS)
            return
        self._connect_to_another_client_with_dht(another_client)

    def _connect_to_another_client_with_dht(self, another_client):
        try:
            another_client_ip = self._our_client.dht.get_data(another_client)['ip']
        except (OSError, TypeError, KeyError) as e:
            self._logger.error(f'Не удалось получить ip клиента [{another_client}]. Ошибка [{e}].')
            CustomMessageBox.show(self, 'Ошибка', f'Не удалось получить ip клиента [{another_client}]. Ошибка [{e}].', CustomMessageType.ERROR)
            return

        if not self._our_client.is_ipv4(another_client_ip):
            self._logger.error(f"Введен некорректный ip-адрес [{another_client_ip}]!"
                               f" Ip-адрес должен быть в формате IPv4!")
            CustomMessageBox.show(self, 'Ошибка', f"Введен некорректный ip-адрес [{another_client_ip}]! Ip-адрес должен быть в формате IPv4!", CustomMessageType.ERROR)
            return
        
        if another_client_ip == self._ip_address:
            self._logger.error("Пока нельзя подключаться самому к себе!")
            CustomMessageBox.show(self, 'Ошибка', "Пока нельзя подключаться самому к себе!", CustomMessageType.ERROR)
            return
        
        # установаем соединение
        threading.Thread(target=self._our_client.connect, args=(another_client_ip, ), daemon=True).start()

    
    def _send_message_to_another_client(self, message: dict):
        self._our_client.get_session(
            self._active_dialogs[self._chats.get_current_dialog().get_interlocutor_id()]['session_id']
        ).send(message)

    def _create_file_from_data(self, data: dict, client_name: str) -> None:
        if data and data['raw_data']:
            os.makedirs(f"{config.paths['dirs']['download']}", exist_ok=True)
            with open(f"{config.paths['dirs']['download']}/{data['filename']}", 'wb') as file:
                file.write(base64.b64decode(data['raw_data']))
            CustomMessageBox.show(self, 'Инфо', f'Получен файл [{data["filename"]}] от [{client_name}].', CustomMessageType.SUCCESS)

    def _create_config(self) -> None:
        try:
            config_filename = config.paths['files']['config']
            with open(config_filename, 'w', encoding='utf-8') as config_file1:
                data1 = {
                    'default_theme': self._style_is_default_theme,
                    'dark_theme': self._style_is_dark_theme,
                    'logger_mode_debug': self._is_logger_mode_debug_var.get()
                }
                json.dump(data1, config_file1)
                self._logger.debug('Конфиг был успешно создан.')
        except IOError:
            self._logger.error(f'Не удалось открыть файл [{config_filename}] для записи!')

    def _prepare_to_close_program(self) -> None:
        
        def __close_program():
            self._logger.debug("Завершаю программу...")
            CustomMessageBox.show(self, 'Инфо', f"Подождите, идет завершение программы...", CustomMessageType.INFO)
            self._our_client.dht.stop()
            self._our_client.close()
            self._create_config()
            self.destroy()

        
        if not self._is_close_program_event:
            self._is_close_program_event = True
            threading.Thread(target=__close_program, daemon=True).start()

    def close(self):
        self._prepare_to_close_program()

    def run(self) -> None:
        self.mainloop()