import json
import os
import threading
import tkinter
from tkinter import ttk
from pydantic import ValidationError
from tkinterdnd2 import TkinterDnD

from enum import Enum
from typing import NamedTuple
from dataclasses import dataclass

from config import config
from dht import DHTPeerProfile, EmptyDHTDataError
from libs.cryptography import Encrypter
from libs.message import MessageData
from libs.mylogger import MyLogger, MyLoggerType
from libs.network import ClientHelper
from libs.utils import strip_bad_symbols
from libs.widgets import CustomMessageBox, CustomMessageType, DialogManager

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

        threading.Thread(target=self._client_helper.handle_dialog, args=(self, self._dialog_manager), daemon=True).start()
        self.protocol("WM_DELETE_WINDOW", self._prepare_to_close_program)

    def _default_init(self) -> None:
        """
            Устанавливает начальные значения для основных атрибутов.
        """
        self._logger_type = MyLoggerType.DEBUG if config.LOGGER.DEBUG_MODE else MyLoggerType.ERROR
        self._current_theme = _default_theme

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

    def _create_menu(self) -> None:
        """
            Создает меню в основном окне.
        """
        menu_main = tkinter.Menu(self._frame_main, tearoff=0)

        # Определение меню для дополнительных настроек
        menu_additional = tkinter.Menu(menu_main, tearoff=0)
        self._is_logger_mode_debug_var = tkinter.BooleanVar(value=True if self._logger_type == MyLoggerType.DEBUG else False)
        self._is_logger_mode_debug_var.trace_add('write',
                                                 (lambda *args: self._logger.setLevel(
                                                     MyLoggerType.DEBUG.value if self._is_logger_mode_debug_var.get()
                                                       else MyLoggerType.ERROR.value)))

        menu_additional.add_checkbutton(label='Логгер в режиме дебага', onvalue=1, offvalue=0,
                                         variable=self._is_logger_mode_debug_var)

        # Меню для выбора темы оформления
        menu_themes = tkinter.Menu(menu_additional, tearoff=0)
        self._change_theme_var = tkinter.IntVar(value=self._current_theme.type.value)
        menu_themes.add_radiobutton(label='Простая тема', variable=self._change_theme_var,
                                           value=_default_theme.type.value, command=self._change_theme)

        if _night_theme.was_loaded:            
            menu_themes.add_radiobutton(label='Тёмная тема', variable=self._change_theme_var,
                                              value=_night_theme.type.value, command=self._change_theme)
        if _light_theme.was_loaded:
            menu_themes.add_radiobutton(label='Светлая тема', variable=self._change_theme_var,
                                              value=_light_theme.type.value, command=self._change_theme)
        
        menu_additional.add_cascade(label='Темы', menu=menu_themes)
        menu_main.add_cascade(label='Дополнительно', menu=menu_additional)

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

        self._frame_my_dht_key = ttk.Frame(self._frame_connection)
        self._frame_my_dht_key.pack(side='left')

        label_my_dht_key = ttk.Label(self._frame_my_dht_key, text='Ваш DHT ключ:')
        label_my_dht_key.pack(padx=5, pady=5)

        self._entry_my_dht_key_var = tkinter.StringVar()
        self._entry_my_dht_key = ttk.Entry(self._frame_my_dht_key, width=30, textvariable=self._entry_my_dht_key_var)
        self._entry_my_dht_key.pack(padx=10, pady=10)

        self._button_enter_my_dht_key = ttk.Button(self._frame_my_dht_key, text='Отправить', width=30, command=self._set_my_dht_key)
        self._button_enter_my_dht_key.pack(padx=10, pady=10)

        self._user_information_has_been_entered = tkinter.BooleanVar(value=False)

        frame_alien_dht_key = ttk.Frame(self._frame_connection)
        frame_alien_dht_key.pack(side='left')

        label_alien_dht_key = ttk.Label(frame_alien_dht_key, text='Чужой DHT ключ:')
        label_alien_dht_key.pack(padx=5, pady=5)

        self._entry_alien_dht_key_var = tkinter.StringVar()
        entry_alien_dht_key = ttk.Entry(frame_alien_dht_key, width=30, textvariable=self._entry_alien_dht_key_var)
        entry_alien_dht_key.pack(padx=10, pady=10)

        button_connect_to_another_client = ttk.Button(frame_alien_dht_key, text='Подключиться/Отключиться',
                                                       width=30, command=self._connect_to_another_user)
        button_connect_to_another_client.pack(padx=10, pady=10)

        def _send_message_to_another_client(message: MessageData) -> None:
            peer_user_id: str = self._dialog_manager.get_current_dialog().get_interlocutor_id()
            self._client_helper.send_message_to_another_client(message, peer_user_id)

        self._dialog_manager = DialogManager(self._frame_main, command=lambda msg: _send_message_to_another_client(msg))
        self._dialog_manager.pack(expand=True, fill='both', padx=10, pady=10)

    def _set_my_dht_key(self) -> None:
        if not self._entry_my_dht_key_var.get():
            self._logger.error("Перед отправкой необходимо ввести свой ключ устройства!")
            CustomMessageBox.show(self, 'Ошибка', "Перед отправкой необходимо ввести свой ключ устройства!", CustomMessageType.ERROR)
            return

        if not self._check_data_for_validity(self._entry_my_dht_key_var.get()):
            self._logger.error(f"В введенном ключе есть недопустимые символы!")
            CustomMessageBox.show(self, 'Ошибка', f"В введенном ключе есть недопустимые символы!", CustomMessageType.ERROR)
            return
        
        self._create_child_window_for_entering_user_info()

    def __set_my_dht_key(self) -> None:
        if not self._user_information_has_been_entered.get():
            return

        self._entry_my_dht_key.config(state='disabled')
        self._button_enter_my_dht_key.config(state='disabled')

        self._client_helper.set_client_info(self._user_id_var.get(), self._user_name_var.get(), self._use_local_ip_var.get())
        ip_address = self._client_helper.get_ip()

        self.title(f"Client: ip[{ip_address}] | key[{self._user_id_var.get()}]")
        self._dialog_manager.set_username(self._user_name_var.get())

        self._logger.debug(f'Добавляю свой ip [{ip_address}] в DHT по ключу [{self._entry_my_dht_key_var.get()}].')
        
        self._client_helper.set_data_to_dht(
            self._entry_my_dht_key_var.get(),
            DHTPeerProfile(
                avaliable_ip=ip_address,
                avaliable_port=config.NETWORK.CLIENT_COMMUNICATION_PORT,
                rsa_public_key=Encrypter.load_rsa_public_key(config.PATHS.KEYS, self._user_id_var.get())
            )
        )

    def _connect_to_another_user(self) -> None:
        if not self._user_information_has_been_entered.get():
            self._logger.error("Перед подключением необходимо ввести свой ключ устройства!")
            CustomMessageBox.show(self, 'Ошибка', "Перед подключением необходимо ввести свой ключ устройства!", CustomMessageType.ERROR)
            return
        
        if not self._entry_alien_dht_key_var.get():
            self._logger.error("Перед подключением необходимо ввести ключ другого устройства!")
            CustomMessageBox.show(self, 'Ошибка', "Перед подключением необходимо ввести ключ другого устройства!", CustomMessageType.ERROR)
            return
        
        if not self._check_data_for_validity(self._entry_alien_dht_key_var.get()):
            self._logger.error(f"В введенном ключе есть недопустимые символы!")
            CustomMessageBox.show(self, 'Ошибка', f"В введенном ключе есть недопустимые символы!", CustomMessageType.ERROR)
            return

        threading.Thread(target=self.__connect_to_another_client, daemon=True).start()

    def __connect_to_another_client(self) -> None:
        try:
            another_client_info: DHTPeerProfile = self._client_helper.get_data_from_dht(self._entry_alien_dht_key_var.get())
        except (OSError, TypeError, ValidationError, EmptyDHTDataError) as e:
            self._logger.error(f'Не удалось получить данные клиента [{self._entry_alien_dht_key_var.get()}]. Ошибка [{e}].')
            CustomMessageBox.show(self, 'Ошибка', f'Не удалось получить ip клиента [{self._entry_alien_dht_key_var.get()}]. Ошибка [{e}].', CustomMessageType.ERROR)
            return
        
        if self._client_helper.is_own_ip(another_client_info.avaliable_ip):
            self._logger.error("Пока нельзя подключаться самому к себе!")
            CustomMessageBox.show(self, 'Ошибка', "Пока нельзя подключаться самому к себе!", CustomMessageType.ERROR)
            return
        
        # установаем соединение
        self._client_helper.connect(another_client_info)

    def _create_child_window_for_entering_user_info(self):
        """
            Создает дочернее окно для ввода дополнительной информации о пользователе.
        """
        window = tkinter.Toplevel(self)
        window.title('Ввод пользовательской информации')
        window.geometry('500x200')
        window.minsize(500, 200)
        window.resizable(False, False)

        try:
            window.iconbitmap(config.FILES.ICONS.MAIN)
        except tkinter.TclError:
            pass

        frame = ttk.Frame(window)
        frame.pack(expand=True, fill='both')

        frame2 = ttk.Frame(frame)
        frame2.pack(fill='x')

        label1 = ttk.Label(frame2, text=f'Введите ваш айди: ')
        label1.pack(padx=15, pady=15, side='left')

        self._user_id_var = tkinter.StringVar()
        entry1 = ttk.Entry(frame2, textvariable=self._user_id_var)
        entry1.pack(padx=15, pady=15, expand=True, fill='x', side='left')

        frame3 = ttk.Frame(frame)
        frame3.pack(fill='x')

        label2 = ttk.Label(frame3, text=f'Введите ваше имя: ')
        label2.pack(padx=15, pady=15, side='left')

        self._user_name_var = tkinter.StringVar()
        entry2 = ttk.Entry(frame3, textvariable=self._user_name_var)
        entry2.pack(padx=15, pady=15, expand=True, fill='x', side='left')

        self._use_local_ip_var = tkinter.BooleanVar(value=False)
        check = ttk.Checkbutton(frame, text='Использовать локальный IP адрес', variable=self._use_local_ip_var)
        check.pack(padx=15, pady=10)

        def _continue():
            nonlocal window
            if not self._user_id_var.get():
                CustomMessageBox.show(window, 'Ошибка', 'Перед продолжением необходимо ввести свой айди!', CustomMessageType.ERROR)
                self._logger.error('Перед продолжением необходимо ввести свой айди!')
                return
            if not self._user_name_var.get():
                CustomMessageBox.show(window, 'Ошибка', 'Перед продолжением необходимо ввести имя пользователя!', CustomMessageType.ERROR)
                self._logger.error('Перед продолжением необходимо ввести имя пользователя!')
                return

            if not self._check_data_for_validity(self._user_id_var.get()):
                CustomMessageBox.show(window, 'Ошибка', 'Введенный айди содержит недопустимые символы!', CustomMessageType.ERROR)
                self._logger.error('Введенный айди содержит недопустимые символы!')
                return

            if not self._check_data_for_validity(self._user_name_var.get()):
                CustomMessageBox.show(window, 'Ошибка', 'Введенное имя содержит недопустимые символы!', CustomMessageType.ERROR)
                self._logger.error('Введенное имя содержит недопустимые символы!')
                return

            self._user_information_has_been_entered.set(True)
            window.destroy()
            threading.Thread(target=self.__set_my_dht_key, daemon=True).start()            


        button = ttk.Button(frame, text='Продолжить', width=30, command=_continue)
        button.pack(padx=15, pady=10)

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
                    'is_logger_debug_mode': self._is_logger_mode_debug_var.get()
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
                    is_logger_debug_mode = data['is_logger_debug_mode']
                    self._logger.debug(f'Значение логгера получено: [{is_logger_debug_mode}]')

                    self._current_theme = (_night_theme if theme_type == _night_theme.type.value
                            else _light_theme if theme_type == _light_theme.type.value else _default_theme)
                    self._logger.debug(f'Значение темы установлено в: [{self._current_theme.name}]')

                    self._logger_type = MyLoggerType.DEBUG if is_logger_debug_mode else MyLoggerType.ERROR
                    self._logger.debug(f'Значение темы логгера в: [{self._logger_type.name}]')


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
            CustomMessageBox.show(self, 'Инфо', f"Подождите, идет завершение программы...", CustomMessageType.INFO)
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
        