from copy import deepcopy
import json
import os
import pyperclip
import threading
import tkinter
from tkinter import ttk
from pydantic import ValidationError
from tkinterdnd2 import TkinterDnD

from enum import Enum
from dataclasses import dataclass

from config import UserIdHashType, config
from dht import DHTPeerProfile, EmptyDHTDataError
from libs.cryptography import Encrypter
from libs.message import MessageData
from libs.mylogger import MyLogger, MyLoggerType
from libs.network import ClientHelper, UserIdType
from libs.structs import ClientInfo
from libs.utils import strip_bad_symbols
import libs.widgets as wg 

class ThemeType(Enum):
    DEFAULT: int = 0
    NIGHT: int = 1
    LIGHT: int = 2

@dataclass
class Theme():
    type: ThemeType
    name: str
    filename: str
    was_loaded: bool = False


_default_theme  = Theme(type=ThemeType.DEFAULT, name=config.THEME.DEFAULT, filename=config.FILES.THEMES.DEFAULT, was_loaded=True)
_night_theme    = Theme(type=ThemeType.NIGHT, name=config.THEME.NIGHT, filename=config.FILES.THEMES.NIGHT)
_light_theme    = Theme(type=ThemeType.LIGHT, name=config.THEME.LIGHT, filename=config.FILES.THEMES.LIGHT)
    

class WinApp(TkinterDnD.Tk):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._default_init()
        self._logger = MyLogger('client', self._logger_type, config.PATHS.LOG_CLIENT, also_use_console=True).logger
        self._client_helper = ClientHelper(self._logger)

        self._loads_from_config()
        self._logger.setLevel(self._logger_type.value)

        self._create_window()

        registered_users = self._client_helper.get_all_registered_users()
        if not registered_users:
            threading.Thread(target=self._create_child_window_for_entering_user_info, args=(True,), daemon=True).start()
        else:
            threading.Thread(target=self._create_sign_in_window, args=(registered_users,), daemon=True).start()

        threading.Thread(target=self._client_helper.handle_dialog, args=(self, self._dialog_manager), daemon=True).start()
        self.protocol("WM_DELETE_WINDOW", self._prepare_to_close_program)

    def _default_init(self) -> None:
        """
            Устанавливает начальные значения для основных атрибутов.
        """
        self._logger_type = MyLoggerType.DEBUG if config.LOGGER.DEBUG_MODE else MyLoggerType.ERROR
        self._current_theme = _default_theme

        self._client_info = ClientInfo()
        self._last_user_id: UserIdType = ''

        self._is_child_window_for_entering_user_info_active = False
        self._was_event_to_close_program = False

    def _create_window(self) -> None:
        """
            Создает и настраивает основные элементы окна.
        """
        self.title(f"Client")
        self.geometry('750x730')
        self.minsize(750, 730)

        try:
            self.iconbitmap(config.FILES.ICONS.MAIN)
        except tkinter.TclError:
            pass

        self._load_themes()

        self._frame_main = ttk.Frame(self)
        self._frame_main.pack(expand=True, fill='both')

        self._create_menu()
        self._create_widgets()

    def _load_themes(self) -> None:
        """
            Загружает и применяет темы оформления.
        """
        self._app_style = ttk.Style(self)

        # Грузим темную тему
        if os.path.exists(_night_theme.filename):
            try:
                self.tk.call("source", _night_theme.filename)
                _night_theme.was_loaded = True
                self._logger.debug(f'Тема [{_night_theme.name}] успешно загружена!')
            except tkinter.TclError:
                self._logger.error(f'Ошибка при открытии файла [{_night_theme.filename}]!')
        
        # Грузим светлую тему
        if os.path.exists(_light_theme.filename):
            try:
                self.tk.call("source", _light_theme.filename)
                _light_theme.was_loaded = True
                self._logger.debug(f'Тема [{_light_theme.name}] успешно загружена!')
            except tkinter.TclError:
                self._logger.error(f'Ошибка при открытии файла [{_light_theme.filename}]!')
            
        # Применяем тему
        try:   
            self._app_style.theme_use(self._current_theme.name)
            self._logger.debug(f'Тема [{self._current_theme.name}] успешно применена!')
        except tkinter.TclError:
            self._.error(f'Не удалось установить стиль [{self._current_theme.name}]!')

    def _change_theme(self, *args) -> None:
        """
            Изменяет тему оформления приложения.

        Args:
            *args: Дополнительные аргументы, не используемые напрямую.
        """
        self._current_theme = _night_theme if self._change_theme_var.get() == _night_theme.type.value \
            else _light_theme if self._change_theme_var.get() == _light_theme.type.value else _default_theme

        self._app_style.theme_use(self._current_theme.name)
        self._logger.debug(f'Тема [{self._current_theme.name}] успешно применена!')

    def _generate_new_sign_up_info(self) -> None:
        """
            Генерирует данные для нового пользователя.
        """
        self._client_info.user_id      = self._client_helper.generate_random_string()
        self._client_info.user_name    = self._client_helper.generate_random_string(number_of_symbols=5)
        self._client_info.user_dht_key = self._client_helper.generate_random_string(number_of_symbols=20)

    def _create_menu(self) -> None:
        """
            Создает меню в основном окне.
        """
        menu_main = tkinter.Menu(self._frame_main, tearoff=0)

        self._is_logger_mode_debug_var = tkinter.BooleanVar(value=True if self._logger_type == MyLoggerType.DEBUG else False)
        self._is_logger_mode_debug_var.trace_add('write',
                                                 (lambda *args: self._logger.setLevel(
                                                     MyLoggerType.DEBUG.value if self._is_logger_mode_debug_var.get()
                                                       else MyLoggerType.ERROR.value)))

        menu_main.add_checkbutton(label='Логгер в режиме дебага', onvalue=1, offvalue=0, variable=self._is_logger_mode_debug_var)

        # Меню для выбора темы оформления
        menu_themes = tkinter.Menu(menu_main, tearoff=0)
        self._change_theme_var = tkinter.IntVar(value=self._current_theme.type.value)
        menu_themes.add_radiobutton(label='Простая тема', variable=self._change_theme_var,
                                           value=_default_theme.type.value, command=self._change_theme)

        if _night_theme.was_loaded:            
            menu_themes.add_radiobutton(label='Тёмная тема', variable=self._change_theme_var,
                                              value=_night_theme.type.value, command=self._change_theme)
        if _light_theme.was_loaded:
            menu_themes.add_radiobutton(label='Светлая тема', variable=self._change_theme_var,
                                              value=_light_theme.type.value, command=self._change_theme)
        
        # Определение меню для дополнительных настроек
        menu_additional = tkinter.Menu(menu_main, tearoff=0)

        def __update(*args):
            self._client_info.use_local_ip = self._use_local_ip_var.get()
            threading.Thread(target=self._update_user_info, daemon=True).start()

        self._use_local_ip_var = tkinter.BooleanVar(value=self._client_info.use_local_ip)
        self._use_local_ip_var.trace_add('write', __update)
        
        menu_additional.add_checkbutton(label='Использовать локальный IP адрес', onvalue=1, offvalue=0, variable=self._use_local_ip_var)
        menu_additional.add_command(label='Cкопировать мой DHT ключ', command=lambda: pyperclip.copy(self._client_info.user_dht_key))
        menu_additional.add_separator()
        menu_additional.add_command(label='Изменить данные аккаунта и сети', command=self._create_child_window_for_entering_user_info)
        menu_additional.add_separator()

        def __logout():
            self._change_account()
            self._client_info = ClientInfo()
            self.title(f"Client")
            self._clear_alien_combobox()
            registered_users = self._client_helper.get_all_registered_users()
            threading.Thread(target=self._create_sign_in_window, args=(registered_users,), daemon=True).start()

        menu_additional.add_command(label='Выйти из аккаунта', command=__logout)

        menu_main.add_cascade(label='Темы', menu=menu_themes)
        menu_main.add_cascade(label='Настройки', menu=menu_additional)

        # Добавление элементов меню на панель
        separator1 = ttk.Separator(self._frame_main)
        separator1.pack(pady=5, fill='x')

        menu_button = ttk.Menubutton(self._frame_main, text='Меню', menu=menu_main, direction="below")
        menu_button.pack()

        separator2 = ttk.Separator(self._frame_main)
        separator2.pack(pady=5, fill='x')

    def _create_widgets(self) -> None:
        """
            Создает виджеты для взаимодействия с пользователем.
        """
        self._frame_connection = ttk.Frame(self._frame_main)
        self._frame_connection.pack()

        self._user_information_has_been_entered = tkinter.BooleanVar(value=False)

        frame_alien_dht_key = ttk.Frame(self._frame_connection)
        frame_alien_dht_key.pack()

        label_alien_dht_key = ttk.Label(frame_alien_dht_key, text='DHT ключ собеседника:')
        label_alien_dht_key.pack(padx=5, pady=5, side='left')

        self._combo_alien_dht_key = wg.JustifiedCombobox(frame_alien_dht_key, width=30, justify=tkinter.CENTER)
        self._combo_alien_dht_key.pack(padx=10, pady=10, side='left')
        wg.Tooltip(self._combo_alien_dht_key, config.WIDGETS.DESCRIPTIONS.ALIEN_DHT_KEY)

        button_connect_to_another_client = ttk.Button(frame_alien_dht_key, text='Подключиться',
                                                       width=30, command=self._connect_to_another_user)
        button_connect_to_another_client.pack(padx=10, pady=10, side='left')

        def _send_message_to_another_client(message: MessageData) -> None:
            peer_user_id_hash: UserIdHashType = self._dialog_manager.get_current_dialog().get_interlocutor_id()
            self._client_helper.send_message_to_another_client(message, peer_user_id_hash)

        self._dialog_manager = wg.DialogManager(self._frame_main, command=lambda msg: _send_message_to_another_client(msg))
        self._dialog_manager.pack(expand=True, fill='both', padx=10, pady=10)

        self._dialog_manager.add_right_click_handler(lambda pid: self._disconnect_from_client(pid))
        self._dialog_manager.add_middle_click_handler(lambda pid: self._disconnect_from_client(pid))

    def _disconnect_from_client(self, peer_id_hash: UserIdHashType) -> None:
        """
            Отключаемся от клиента с заданным peer_id_hash.

        Args:
            peer_id (UserIdType): Идентификатор собеседника
        """
        if self._client_helper.is_dialog_active(peer_id_hash):
            self._logger.debug(f"Отключаюсь от {peer_id_hash}.")
            self._client_helper.close_session(peer_id_hash)
            wg.CustomMessageBox.show(self, 'Инфо', f'Общение с [{peer_id_hash}] завершено!', wg.CustomMessageType.SUCCESS)

    def _connect_to_another_user(self) -> None:
        if not self._client_info.user_dht_key:
            self._logger.error("Перед подключением необходимо ввести свой DHT ключ!")
            wg.CustomMessageBox.show(self, 'Ошибка', "Перед подключением необходимо ввести свой DHT ключ!", wg.CustomMessageType.ERROR)
            return
        
        if not self._combo_alien_dht_key.get():
            self._logger.error("Перед подключением необходимо ввести DHT ключ собеседника!")
            wg.CustomMessageBox.show(self, 'Ошибка', "Перед подключением необходимо ввести DHT ключ собеседника!", wg.CustomMessageType.ERROR)
            return
        
        if not self._check_data_for_validity(self._combo_alien_dht_key.get()):
            self._logger.error(f"В введенном DHT ключе есть недопустимые символы!")
            wg.CustomMessageBox.show(self, 'Ошибка', f"В введенном DHT ключе есть недопустимые символы!", wg.CustomMessageType.ERROR)
            return

        threading.Thread(target=self.__connect_to_another_client, daemon=True).start()

    def __connect_to_another_client(self) -> None:
        try:
            another_client_info: DHTPeerProfile = self._client_helper.get_data_from_dht(self._combo_alien_dht_key.get())
        except (OSError, TypeError, ValidationError, EmptyDHTDataError) as e:
            self._logger.error(f'Не удалось получить данные клиента [{self._combo_alien_dht_key.get()}].')
            wg.CustomMessageBox.show(self, 'Ошибка', f'Не удалось получить ip клиента [{self._combo_alien_dht_key.get()}].\n\nОшибка [{e}].', wg.CustomMessageType.ERROR)
            return
        
        if self._client_info.dht_peers_keys.add_new_dht_key(self._client_info.dht_node_ip, self._combo_alien_dht_key.get()):
            self._client_helper.update_dht_peers_keys(self._client_info.dht_peers_keys)
        
        # if self._client_helper.is_own_ip(another_client_info.avaliable_ip):
        #     self._logger.error("Пока нельзя подключаться самому к себе!")
        #     wg.CustomMessageBox.show(self, 'Ошибка', "Пока нельзя подключаться самому к себе!", wg.CustomMessageType.ERROR)
        #     return
        
        # установаем соединение
        self._client_helper.connect(another_client_info)

    def _create_sign_in_window(self, registered_users: list[UserIdType]):
        """
            Создает дочернее окно для входа в аккаунт.
        """
        child_window = tkinter.Toplevel(self)
        child_window.title('Авторизация')
        child_window.geometry('500x190')
        child_window.resizable(False, False)

        try:
            child_window.iconbitmap(config.FILES.ICONS.MAIN)
        except tkinter.TclError:
            pass

        def __close():
                self.close()

        child_window.protocol("WM_DELETE_WINDOW", __close)

        frame_main = ttk.Frame(child_window)
        frame_main.pack(expand=True, fill='both')

        frame_login = ttk.Frame(frame_main)
        frame_login.pack(fill='x')

        label_id = ttk.Label(frame_login, text=f'ID пользователя: ', width=28)
        label_id.pack(padx=15, pady=15, side='left')

        combo_login = wg.JustifiedCombobox(frame_login, justify=tkinter.CENTER)
        combo_login.pack(padx=15, pady=15, expand=True, fill='x', side='left')
        wg.Tooltip(combo_login, config.WIDGETS.DESCRIPTIONS.USER_ID)

        registered_users.sort()
        for user_id in registered_users:
            combo_login['values'] = (*combo_login['values'], user_id)
        
        if self._last_user_id and self._last_user_id in registered_users:
            combo_login.current(registered_users.index(self._last_user_id))

        frame_password = ttk.Frame(frame_main)
        frame_password.pack(fill='x')

        label_password = ttk.Label(frame_password, text=f'Пароль: ', width=16)
        label_password.pack(padx=15, pady=15, side='left')

        user_password_var = tkinter.StringVar()
        entry_password = ttk.Entry(frame_password, textvariable=user_password_var, show="+", justify=tkinter.CENTER)
        
        check_pass_var = tkinter.BooleanVar(value=True)
        check_pass = ttk.Checkbutton(frame_password, text='[Скрыть]', variable=check_pass_var,
                                    command = lambda: entry_password.config(show="+" if check_pass_var.get() else ""))
        check_pass.pack(padx=5, pady=15, side='left')
        entry_password.pack(padx=15, pady=15, expand=True, fill='x', side='left')
        wg.Tooltip(entry_password, config.WIDGETS.DESCRIPTIONS.USER_PASSWORD)

        frame_buttons = ttk.Frame(frame_main)
        frame_buttons.pack()

        def _sign_in(login: str, password: str):
            nonlocal child_window
            nonlocal registered_users

            if not login:
                wg.CustomMessageBox.show(child_window, 'Ошибка', 'Перед продолжением необходимо ввести ID пользователя!', wg.CustomMessageType.ERROR)
                self._logger.error('Перед продолжением необходимо ввести ID пользователя!')
                return
            
            if not password:
                wg.CustomMessageBox.show(child_window, 'Ошибка', 'Перед продолжением необходимо ввести пароль от аккаунта!', wg.CustomMessageType.ERROR)
                self._logger.error('Перед продолжением необходимо ввести пароль от аккаунта!')
                return
            
            if login not in registered_users:
                wg.CustomMessageBox.show(child_window, 'Ошибка', f'Пользователь [{login}] не зарегистрирован!', wg.CustomMessageType.ERROR)
                self._logger.error(f'Пользователь [{login}] не зарегистрирован!')
                return

            if not self._client_helper.check_password(login, password):
                wg.CustomMessageBox.show(child_window, 'Ошибка', 'Введен неправильный пароль!', wg.CustomMessageType.ERROR)
                self._logger.error('Введен неправильный пароль!')
                return
            
            if not self._client_helper.check_password(login, password, expanded=True):
                wg.CustomMessageBox.show(child_window, 'Ошибка', 'Введен пароль корректен по хэшу, но не подходит для расшифровки ключей!\n\nВозможно кто-то подменил ваш пароль!', wg.CustomMessageType.ERROR)
                self._logger.error('Введен пароль совпадает корректен по хэшу, но не подходит для расшифровки ключей! Возможно кто-то подменил ваш пароль!')
                return
            
            self._client_info = self._client_helper.load_user_info(login, password)
            self._pull_alien_combobox()

            threading.Thread(target=self._use_local_ip_var.set, args=(self._client_info.use_local_ip ,), daemon=True).start()
            child_window.destroy()

        def _sign_up():
            nonlocal child_window
            child_window.destroy()
            self._create_child_window_for_entering_user_info(first_initialization=True)

        button_sign_in = ttk.Button(frame_buttons, text='Войти', width=25,
                                    command=lambda: _sign_in(
                                        combo_login.get(),
                                        self._client_helper.extend_to_32_bytes(user_password_var.get())
                                    ))
        button_sign_in.pack(padx=15, pady=15, side='left')

        button_sign_up = ttk.Button(frame_buttons, text='Зарегистрироваться', width=25, command=lambda: _sign_up())
        button_sign_up.pack(padx=15, pady=15, side='left')

        # Захват ввода для модального окна
        child_window.grab_set()

        # Ограничение доступа к другим окнам до закрытия этого окна
        child_window.wait_window()
        self.deiconify()

    def _clear_alien_combobox(self):
        """
            Отчищает комбобокс значений DHT ключей собеседников.
        """
        self._combo_alien_dht_key.set('')
        self._combo_alien_dht_key['values'] = ()

    def _pull_alien_combobox(self):
        """
            Заполняет комбобок значениями DHT ключей собеседников для текущего DHT-node IP.
        """
        self._clear_alien_combobox()

        for dht_node in self._client_info.dht_peers_keys.nodes_history:
            if dht_node.ip_address == self._client_info.dht_node_ip:
                for dht_key in dht_node.dht_keys:
                    self._combo_alien_dht_key['values'] = (*self._combo_alien_dht_key['values'], dht_key)

    def _create_child_window_for_entering_user_info(self, first_initialization: bool = False):
        """
            Создает дочернее окно для ввода дополнительной информации о пользователе.
        """
        if self._is_child_window_for_entering_user_info_active is True:
            return
        self._is_child_window_for_entering_user_info_active = True

        self.__child_window = tkinter.Toplevel(self)
        self.__child_window.title('Ввод пользовательской информации')
        self.__child_window.geometry('500x675')
        self.__child_window.resizable(False, False)

        if first_initialization:
            self._generate_new_sign_up_info()
            self.__child_window.protocol("WM_DELETE_WINDOW", self.close)
        else:
            def __close():
                self._is_child_window_for_entering_user_info_active = False
                self.__child_window.destroy()

            self.__child_window.protocol("WM_DELETE_WINDOW", __close)

        try:
            self.__child_window.iconbitmap(config.FILES.ICONS.MAIN)
        except tkinter.TclError:
            pass

        frame_main = ttk.Frame(self.__child_window)
        frame_main.pack(expand=True, fill='both')

        labelframe_account_settings  = ttk.LabelFrame(frame_main, text="Настройки аккаунта")
        labelframe_account_settings.pack(padx=15, pady=15, expand=True, fill='both')

        frame_id = ttk.Frame(labelframe_account_settings)
        frame_id.pack(fill='x')

        label_id = ttk.Label(frame_id, text=f'ID пользователя: ', width=28)
        label_id.pack(padx=15, pady=15, side='left')

        self.__user_id_var_temp = tkinter.StringVar(value=self._client_info.user_id)
        entry_id = ttk.Entry(frame_id, textvariable=self.__user_id_var_temp, state='disabled')
        entry_id.pack(padx=15, pady=15, expand=True, fill='x', side='left')
        wg.Tooltip(entry_id, config.WIDGETS.DESCRIPTIONS.USER_ID)

        registered_users = []
        if first_initialization:
            registered_users = self._client_helper.get_all_registered_users()
            entry_id.configure(state='normal')

            frame_password = ttk.Frame(labelframe_account_settings)
            frame_password.pack(fill='x')

            label_password = ttk.Label(frame_password, text=f'Пароль: ', width=16)
            label_password.pack(padx=15, pady=15, side='left')

            self.__user_password_var_temp = tkinter.StringVar()
            entry_password = ttk.Entry(frame_password, textvariable=self.__user_password_var_temp, show="+")
            
            check_pass_var = tkinter.BooleanVar(value=True)
            check_pass = ttk.Checkbutton(frame_password, text='[Скрыть]', variable=check_pass_var,
                                        command = lambda: entry_password.config(show="+" if check_pass_var.get() else ""))
            check_pass.pack(padx=5, pady=15, side='left')
            entry_password.pack(padx=15, pady=15, expand=True, fill='x', side='left')
            wg.Tooltip(entry_password,  config.WIDGETS.DESCRIPTIONS.USER_PASSWORD)

        frame_name = ttk.Frame(labelframe_account_settings)
        frame_name.pack(fill='x')

        label_name = ttk.Label(frame_name, text=f'Имя пользователя: ', width=28)
        label_name.pack(padx=15, pady=15, side='left')

        self.__user_name_var_temp = tkinter.StringVar(value=self._client_info.user_name)
        entry_name = ttk.Entry(frame_name, textvariable=self.__user_name_var_temp)
        entry_name.pack(padx=15, pady=15, expand=True, fill='x', side='left')
        wg.Tooltip(entry_name, config.WIDGETS.DESCRIPTIONS.USER_NAME)

        labelframe_network_settings = ttk.LabelFrame(frame_main, text="Настройки сети")
        labelframe_network_settings.pack(padx=15, pady=15, expand=True, fill='both')

        self.__use_local_ip_var_temp = tkinter.BooleanVar(value=self._client_info.use_local_ip)
        check_ip = ttk.Checkbutton(labelframe_network_settings, text='Использовать локальный IP адрес', variable=self.__use_local_ip_var_temp)
        check_ip.pack(padx=15, pady=10)

        frame_dht_key = ttk.Frame(labelframe_network_settings)
        frame_dht_key.pack(fill='x')

        label_dht_key = ttk.Label(frame_dht_key, text=f'DHT-ключ пользователя: ', width=28)
        label_dht_key.pack(padx=15, pady=15, side='left')

        self.__user_dht_key_var_temp = tkinter.StringVar(value=self._client_info.user_dht_key)
        entry_dht_key = ttk.Entry(frame_dht_key, textvariable=self.__user_dht_key_var_temp)
        entry_dht_key.pack(padx=15, pady=15, expand=True, fill='x', side='left')
        wg.Tooltip(entry_dht_key, config.WIDGETS.DESCRIPTIONS.USER_DHT_KEY)

        frame_dht_ip = ttk.Frame(labelframe_network_settings)
        frame_dht_ip.pack(fill='x')

        label_dht_ip = ttk.Label(frame_dht_ip, text=f'IP адрес DHT-node: ', width=28)
        label_dht_ip.pack(padx=15, pady=15, side='left')

        self.__dht_node_ip_var_temp = wg.PlaceholderVar(value=self._client_info.dht_node_ip)
        entry_dht_ip = wg.PlaceholderEntry(frame_dht_ip, placeholder=config.NETWORK.DHT.IP, textvariable=self.__dht_node_ip_var_temp)
        entry_dht_ip.pack(padx=15, pady=15, expand=True, fill='x', side='left')
        wg.Tooltip(entry_dht_ip, config.WIDGETS.DESCRIPTIONS.DHT_NODE_IP)

        frame_dht_port = ttk.Frame(labelframe_network_settings)
        frame_dht_port.pack(fill='x')

        label_dht_port = ttk.Label(frame_dht_port, text=f'Порт DHT-node: ', width=28)
        label_dht_port.pack(padx=15, pady=15, side='left')

        self.__dht_node_port_var_temp = wg.PlaceholderVar(value=self._client_info.dht_node_port)
        entry_dht_port = wg.PlaceholderEntry(frame_dht_port, placeholder=str(config.NETWORK.DHT.PORT), textvariable=self.__dht_node_port_var_temp)
        entry_dht_port.pack(padx=15, pady=15, expand=True, fill='x', side='left')
        wg.Tooltip(entry_dht_port, config.WIDGETS.DESCRIPTIONS.DHT_NODE_PORT)

        frame_app_port = ttk.Frame(labelframe_network_settings)
        frame_app_port.pack(fill='x')

        label_app_port = ttk.Label(frame_app_port, text=f'Порт приложения: ', width=28)
        label_app_port.pack(padx=15, pady=15, side='left')

        self.__app_port_var_temp = wg.PlaceholderVar(value=self._client_info.application_port)
        entry_app_port = wg.PlaceholderEntry(frame_app_port, placeholder=str(config.NETWORK.CLIENT_COMMUNICATION_PORT), textvariable=self.__app_port_var_temp)
        entry_app_port.pack(padx=15, pady=15, expand=True, fill='x', side='left')
        wg.Tooltip(entry_app_port, config.WIDGETS.DESCRIPTIONS.APP_PORT)

        frame_dht_client_port = ttk.Frame(labelframe_network_settings)
        frame_dht_client_port.pack(fill='x')

        label_dht_client_port = ttk.Label(frame_dht_client_port, text=f'Порт DHT-node клиента: ', width=28)
        label_dht_client_port.pack(padx=15, pady=15, side='left')

        self.__dht_client_port_var_temp = wg.PlaceholderVar(value=self._client_info.dht_client_port)
        entry_dht_client_port = wg.PlaceholderEntry(frame_dht_client_port, placeholder=str(config.NETWORK.DHT_CLIENT_PORT), textvariable=self.__dht_client_port_var_temp)
        entry_dht_client_port.pack(padx=15, pady=15, expand=True, fill='x', side='left')
        wg.Tooltip(entry_dht_client_port, config.WIDGETS.DESCRIPTIONS.DHT_CLIENT_PORT)

        button = ttk.Button(frame_main, text='Продолжить', width=30, command=lambda: self.__apply_changes(registered_users, first_initialization))
        button.pack(padx=15, pady=10)

        # Захват ввода для модального окна
        self.__child_window.grab_set()

        # Ограничение доступа к другим окнам до закрытия этого окна
        self.__child_window.wait_window()
        self.deiconify()

    def __apply_changes(self, registered_users: list[UserIdType], first_initialization: bool = False) -> None:        
        if first_initialization:
            if not self.__user_id_var_temp.get():
                wg.CustomMessageBox.show(self.__child_window, 'Ошибка', 'Перед продолжением необходимо ввести свой ID!', wg.CustomMessageType.ERROR)
                self._logger.error('Перед продолжением необходимо ввести свой айди!')
                return
            
            if self.__user_id_var_temp.get() in registered_users:
                wg.CustomMessageBox.show(self.__child_window, 'Ошибка', f'Пользователь с ID [{self.__user_id_var_temp.get()}] уже зарегистрирован!', wg.CustomMessageType.ERROR)
                self._logger.error(f'Пользователь с ID [{self.__user_id_var_temp.get()}] уже зарегистрирован!')
                return

            if not self.__user_password_var_temp.get():
                wg.CustomMessageBox.show(self.__child_window, 'Ошибка', 'Перед продолжением необходимо ввести пароль от аккаунта!', wg.CustomMessageType.ERROR)
                self._logger.error('Перед продолжением необходимо ввести пароль от аккаунта!')
                return
        
        if not self.__user_name_var_temp.get():
            wg.CustomMessageBox.show(self.__child_window, 'Ошибка', 'Перед продолжением необходимо ввести имя пользователя!', wg.CustomMessageType.ERROR)
            self._logger.error('Перед продолжением необходимо ввести имя пользователя!')
            return
        
        if not self.__user_dht_key_var_temp.get():
            wg.CustomMessageBox.show(self.__child_window, 'Ошибка', 'Перед продолжением необходимо ввести ваш DHT ключ!', wg.CustomMessageType.ERROR)
            self._logger.error('Перед продолжением необходимо ввести ваш DHT ключ!')
            return
        
        if not self.__dht_node_ip_var_temp.get():
            wg.CustomMessageBox.show(self.__child_window, 'Ошибка', 'Перед продолжением необходимо ввести IP адрес DHT-ноды!', wg.CustomMessageType.ERROR)
            self._logger.error('Перед продолжением необходимо ввести IP адрес DHT-ноды!')
            return
        
        if not self.__dht_node_port_var_temp.get():
            wg.CustomMessageBox.show(self.__child_window, 'Ошибка', 'Перед продолжением необходимо ввести порт DHT-ноды!', wg.CustomMessageType.ERROR)
            self._logger.error('Перед продолжением необходимо ввести порт DHT-ноды!')
            return
        
        if not self.__app_port_var_temp.get():
            wg.CustomMessageBox.show(self.__child_window, 'Ошибка', 'Перед продолжением необходимо ввести порт приложения!', wg.CustomMessageType.ERROR)
            self._logger.error('Перед продолжением необходимо ввести порт приложения!')
            return
        
        if not self.__dht_client_port_var_temp.get():
            wg.CustomMessageBox.show(self.__child_window, 'Ошибка', 'Перед продолжением необходимо ввести порт DHT-ноды клиента!', wg.CustomMessageType.ERROR)
            self._logger.error('Перед продолжением необходимо ввести порт DHT-ноды клиента!')
            return
        
        if not self._client_helper.is_valid_ipv4(self.__dht_node_ip_var_temp.get()):
            wg.CustomMessageBox.show(self.__child_window, 'Ошибка', f'Введен некорректный IPv4 адрес DHT-ноды [{self.__dht_node_ip_var_temp.get()}]!', wg.CustomMessageType.ERROR)
            self._logger.error(f'Введен некорректный IPv4 адрес DHT-ноды [{self.__dht_node_ip_var_temp.get()}]!')
            return
        
        if not self._client_helper.is_valid_port(self.__dht_node_port_var_temp.get()):
            wg.CustomMessageBox.show(self.__child_window, 'Ошибка', f'Введен некорректный порт DHT-ноды [{self.__dht_node_port_var_temp.get()}]!', wg.CustomMessageType.ERROR)
            self._logger.error(f'Введен некорректный порт DHT-ноды [{self.__dht_node_port_var_temp.get()}]!')
            return
        
        if not self._client_helper.is_port_avaliable(int(self.__dht_node_port_var_temp.get())):
            wg.CustomMessageBox.show(self.__child_window, 'Ошибка', f'Введённый порт DHT-ноды [{self.__dht_node_port_var_temp.get()}] недоступен!', wg.CustomMessageType.ERROR)
            self._logger.error(f'Введённый порт DHT-ноды [{self.__dht_node_port_var_temp.get()}] недоступен!')
            return
        
        if not self._client_helper.is_valid_port(self.__app_port_var_temp.get()):
            wg.CustomMessageBox.show(self.__child_window, 'Ошибка', f'Введен некорректный порт приложения [{self.__app_port_var_temp.get()}]!', wg.CustomMessageType.ERROR)
            self._logger.error(f'Введен некорректный порт приложения [{self.__app_port_var_temp.get()}]!')
            return
        
        if not self._client_helper.is_port_avaliable(int(self.__app_port_var_temp.get())):
            wg.CustomMessageBox.show(self.__child_window, 'Ошибка', f'Введённый порт приложения [{self.__app_port_var_temp.get()}] недоступен!', wg.CustomMessageType.ERROR)
            self._logger.error(f'Введённый порт приложения [{self.__app_port_var_temp.get()}] недоступен!')
            return
        
        if not self._client_helper.is_valid_port(self.__dht_client_port_var_temp.get()):
            wg.CustomMessageBox.show(self.__child_window, 'Ошибка', f'Введен некорректный порт DHT-ноды клиента [{self.__dht_client_port_var_temp.get()}]!', wg.CustomMessageType.ERROR)
            self._logger.error(f'Введен некорректный порт DHT-ноды клиента [{self.__dht_client_port_var_temp.get()}]!')
            return
        
        if not self._client_helper.is_port_avaliable(int(self.__dht_client_port_var_temp.get())):
            wg.CustomMessageBox.show(self.__child_window, 'Ошибка', f'Введённый порт DHT-ноды клиента [{self.__dht_client_port_var_temp.get()}] недоступен!', wg.CustomMessageType.ERROR)
            self._logger.error(f'Введённый порт DHT-ноды клиента [{self.__dht_client_port_var_temp.get()}] недоступен!')
            return

        if self.__dht_client_port_var_temp.get() == self.__app_port_var_temp.get():
            wg.CustomMessageBox.show(self.__child_window, 'Ошибка', f'Порт приложения и порт DHT-ноды клиента должны отличаться!', wg.CustomMessageType.ERROR)
            self._logger.error(f'Порт приложения и порт DHT-ноды клиента должны отличаться!')
            return

        if not self._check_data_for_validity(self.__user_id_var_temp.get()):
            wg.CustomMessageBox.show(self.__child_window, 'Ошибка', 'Введенный ID содержит недопустимые символы!', wg.CustomMessageType.ERROR)
            self._logger.error('Введенный айди содержит недопустимые символы!')
            return

        if not self._check_data_for_validity(self.__user_name_var_temp.get()):
            wg.CustomMessageBox.show(self.__child_window, 'Ошибка', 'Введенное имя содержит недопустимые символы!', wg.CustomMessageType.ERROR)
            self._logger.error('Введенное имя содержит недопустимые символы!')
            return
        
        if not self._check_data_for_validity(self.__user_dht_key_var_temp.get()):
            self._logger.error(f"В введенном DHT ключе есть недопустимые символы!")
            wg.CustomMessageBox.show(self, 'Ошибка', f"В введенном DHT ключе есть недопустимые символы!", wg.CustomMessageType.ERROR)
            return
        
        if self._client_info.user_id == self.__user_id_var_temp.get() and \
            self._client_info.user_name == self.__user_name_var_temp.get() and \
                self._client_info.user_dht_key == self.__user_dht_key_var_temp.get() and \
                    self._client_info.dht_node_ip == self.__dht_node_ip_var_temp.get() and \
                        self._client_info.dht_node_port == self.__dht_node_port_var_temp.get() and \
                            self._client_info.application_port == self.__app_port_var_temp.get() and \
                                self._client_info.dht_client_port == self.__dht_client_port_var_temp.get() and \
                                    self._use_local_ip_var.get() == self.__use_local_ip_var_temp.get():
            self._is_child_window_for_entering_user_info_active = False
            self.__child_window.destroy()
            return

        if first_initialization:
            self._client_info.user_id       = self.__user_id_var_temp.get()
            self._client_info.user_password = self._client_helper.extend_to_32_bytes(self.__user_password_var_temp.get())
            self._client_info.user_id_hash  = self._client_helper.get_hash(self._client_info.user_id, len(self._client_info.user_id) + config.USER_ID_HASH_POSTFIX_SIZE)
            self._client_info.user_password_hash  = self._client_helper.get_hash(self._client_info.user_password)

        if self._client_info.dht_node_ip != self.__dht_node_ip_var_temp.get():
            self._client_info.dht_node_ip = self.__dht_node_ip_var_temp.get()
            self._pull_alien_combobox()

        self._client_info.user_name        = self.__user_name_var_temp.get()
        self._client_info.user_dht_key     = self.__user_dht_key_var_temp.get()
        self._client_info.dht_node_port    = int(self.__dht_node_port_var_temp.get())
        self._client_info.application_port = int(self.__app_port_var_temp.get())
        self._client_info.dht_client_port  = int(self.__dht_client_port_var_temp.get())
        self._client_info.use_local_ip     = self.__use_local_ip_var_temp.get()

        was_use_local_ip_var_changed = True if self._use_local_ip_var.get() != self.__use_local_ip_var_temp.get() else False

        if was_use_local_ip_var_changed:
            self._use_local_ip_var.set(self.__use_local_ip_var_temp.get())
        else:
            threading.Thread(target=self._update_user_info, daemon=True).start()
        
        self._is_child_window_for_entering_user_info_active = False
        self.__child_window.destroy()

    def _change_account(self):
        """
            Выходит из текущего аккаунта, закрывая все соединения и диалоги для данного пользователя.
        """
        self._client_helper.relogin()
        self._dialog_manager.close_all()

    def _update_user_info(self):
        """
            Обрабатывает данные, введённые пользователем.
        """
        wg.CustomMessageBox.show(self, 'Инфо', 'Подождите, идет загрузка аккаунта.', wg.CustomMessageType.INFO)

        self._last_user_id = self._client_info.user_id
        self._client_helper.set_client_info(self._dialog_manager, deepcopy(self._client_info))

        try:
            self._client_helper.save_account()
            self._logger.debug(f'Сохраняю аккаунт [{self._client_info.user_id}] в базу данных.')
        except Exception:
            self._logger.debug(f'Обновляю аккаунт [{self._client_info.user_id}] в базе данных.')
            self._client_helper.update_account()

        ip_address = self._client_helper.get_ip()

        self.title(f"Client: ip[{ip_address}] | id[{self._client_info.user_id}] | name[{self._client_info.user_name}]")
        self._dialog_manager.set_user_name(self._client_info.user_name)

        self._logger.debug(f'Добавляю свой ip [{ip_address}] в DHT по ключу [{self._client_info.user_dht_key}].')
        
        def __set_data():
            self._client_helper.set_data_to_dht(
                self._client_info.user_dht_key,
                DHTPeerProfile(
                    avaliable_ip=ip_address,
                    avaliable_port=self._client_info.application_port,
                    rsa_public_key=Encrypter.load_rsa_public_key(
                        config.PATHS.KEYS,
                        self._client_info.user_id_hash,
                        self._client_info.user_password
                    )
                )
            )
        
        try:
            __set_data()
        except ValueError:
            __set_data()

    def _check_data_for_validity(self, data: str) -> bool:
        """
            Проверяет строку на наличие недопустимых символов.

        Args:
            data (str): Исходная строка

        Returns:
            bool: Валидна ли переданная строка (нет недопустимых символов)
        """
        if data != strip_bad_symbols(data):
            return False
        return True

    def _create_config(self) -> None:
        """
            Создает или перезаписывает файл конфигурации с текущими настройками приложения.
        """
        try:
            with open(config.FILES.CONFIG, 'w', encoding='utf-8') as config_file:
                data = {
                    'current_theme': self._current_theme.type.value,
                    'is_logger_debug_mode': self._is_logger_mode_debug_var.get(),
                    'last_user_id': self._last_user_id
                }
                json.dump(data, config_file)
                self._logger.debug('Конфиг был успешно создан.')
        except IOError:
            self._logger.error(f'Не удалось открыть файл [{config.FILES.CONFIG}] для записи!')

    def _loads_from_config(self) -> None:
        """
            Загружает настройки из файла конфигурации, если он существует.
        """

        if not os.path.exists(config.FILES.CONFIG) or not os.path.isfile(config.FILES.CONFIG):
            self._default_init()
            return

        # Если существует файл конфигурации, то загружаемся с него
        try:
            with open(config.FILES.CONFIG, 'r', encoding='utf-8') as config_file:
                try:
                    data = json.load(config_file)
                    theme_type = data['current_theme']
                    self._logger.debug(f'Значение темы получено: [{theme_type}]')
                    
                    self._current_theme = (_night_theme if theme_type == _night_theme.type.value
                            else _light_theme if theme_type == _light_theme.type.value else _default_theme)
                    self._logger.debug(f'Значение темы установлено в: [{self._current_theme.name}]')

                    is_logger_debug_mode = data['is_logger_debug_mode']
                    self._logger.debug(f'Значение логгера получено: [{is_logger_debug_mode}]')
                    
                    self._logger_type = MyLoggerType.DEBUG if is_logger_debug_mode else MyLoggerType.ERROR
                    self._logger.debug(f'Значение логгера установлено в: [{self._logger_type.name}]')

                    self._last_user_id = data['last_user_id']
                    self._logger.debug(f'Значение last_user_id получено и установлено в: [{self._last_user_id}]')

                except json.decoder.JSONDecodeError:
                    self._logger.error(f'Ошибка при разборе файла [{config.FILES.CONFIG}]!')
                    self._default_init()
                except KeyError:
                    self._logger.error(f'Ошибка при попытке извлечь данные. '
                                    f'Видимо файл [{config.FILES.CONFIG}] был ошибочно записан, либо некорректно изменён!')
                    self._default_init()
        except IOError:
            self._logger.error(f'Не удалось открыть файл [{config.FILES.CONFIG}] для чтения!')
            self._default_init()

    def _prepare_to_close_program(self) -> None:
        """
            Подготавливает программу к закрытию, сохраняя настройки и освобождая ресурсы.
        """
        def __close_program():
            self._logger.debug("Завершаю программу...")
            wg.CustomMessageBox.show(self, 'Инфо', f"Подождите, идет завершение программы...", wg.CustomMessageType.INFO)
            self._client_helper.close()
            self._create_config()
            self.destroy()

        
        if not self._was_event_to_close_program:
            self._was_event_to_close_program = True
            threading.Thread(target=__close_program, daemon=True).start()

    def close(self) -> None:
        """
            Закрывает приложение, активируя процесс подготовки к закрытию.
        """
        self._prepare_to_close_program()    

    def run(self) -> None:
        """
            Запускает главный цикл событий окна.
        """
        try:
            self.mainloop()
        except (KeyboardInterrupt, OSError):
            self._logger.error('Вынужденное небезопасное завершение работы программы! Пожалуйста, завершайте программу через кнопку "Закрыть"')
            self.destroy()
        