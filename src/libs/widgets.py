import platform
import threading
import tkinter as tk
from tkinter import ttk
from tkinterdnd2 import DND_FILES

import os
import random
import string

import base64
import pyperclip
from PIL import Image, ImageTk
from enum import Enum

from typing import Any, Callable, List, NamedTuple, Optional

import pytz
from datetime import datetime

from config import config
from libs.message import *

class CustomMessageType(Enum):
    ANY = 'ANY'
    INFO = 'INFO'
    WARNING = 'WARNING'
    ERROR = 'ERROR'
    SUCCESS = 'SUCCESS'

class _MessageBox(tk.Toplevel):
    def __init__(self, master: Any, title: str, message: str, message_type: CustomMessageType = CustomMessageType.ANY):
        super().__init__(master)
        self.title(title)
        self._message = message
        self._message_type = message_type

        if message_type == CustomMessageType.INFO:
            self._image_path = config.FILES.ICONS.INFO_L
        elif message_type == CustomMessageType.WARNING:
            self._image_path = config.FILES.ICONS.WARNING_L
        elif message_type == CustomMessageType.ERROR:
            self._image_path = config.FILES.ICONS.ERROR_L
        elif message_type == CustomMessageType.SUCCESS:
            self._image_path = config.FILES.ICONS.SUCCESS_L
        else:
            self._image_path = config.FILES.ICONS.MAIN

        self._icon_path = config.FILES.ICONS.MAIN

    def create_widgets(self):
        self.configure_window()
        self.create_message_frame()
        self.create_buttons_frame()

    def configure_window(self):
        self.resizable(False, False)
        self.geometry(self.calculate_geometry())

        try:
            self.iconbitmap(self._icon_path)
        except tk.TclError:
            pass

        self._frame_main = ttk.Frame(self)
        self._frame_main.pack(expand=True, fill='both')

    def calculate_geometry(self, width=360, height=150):
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = (screen_width - width + random.randint(-50, 50)) // 2
        y = (screen_height - height + random.randint(-50, 50)) // 2
        return f'{width}x{height}+{x}+{y}'

    def create_message_frame(self):
        frame = ttk.Frame(self._frame_main)
        frame.pack(expand=True, fill=tk.BOTH)

        try:
            image = ImageTk.PhotoImage(Image.open(self._image_path))
            label_image = ttk.Label(frame, image=image) # type: ignore
            label_image.image = image  # keep a reference! # type: ignore
            label_image.pack(side=tk.LEFT, padx=10, pady=10)
        except Exception:
            pass

        label_text = ttk.Label(frame, text=self._message, wraplength=250)
        label_text.pack(side=tk.LEFT, padx=10, pady=10)

    def create_buttons_frame(self):
        frame = ttk.Frame(self._frame_main)
        frame.pack()

        button_ok = ttk.Button(frame, text="OK", command=self.destroy)
        button_ok.pack(side=tk.LEFT, padx=10, pady=10)

        button_copy = ttk.Button(frame, text="Копировать", command=self.copy_text)
        button_copy.pack(side=tk.LEFT, padx=10, pady=10)

    def copy_text(self):
        pyperclip.copy(self._message)

    def run(self, blocking: bool = False) -> None:
        self.create_widgets()

        if blocking:
            # Захват ввода для модального окна
            self.grab_set()
            # Ограничение доступа к другим окнам до закрытия этого окна
            self.wait_window()

class CustomMessageBox:
    @staticmethod
    def show(master: Any, title: str, message: str, message_type: CustomMessageType = CustomMessageType.ANY, blocking: bool = False):
        # Создаем и показываем конкретный тип сообщения
        _MessageBox(master, title, message, message_type).run(blocking)


class ClientDecision(Enum):
    NONE = -1
    YES = 0
    NO = 1

class _YesNoDialog(tk.Toplevel):
    def __init__(self, master: Any, title: str, message: str):
        super().__init__(master)
        self.title(title)
        self._message = message
        self._icon_path = config.FILES.ICONS.MAIN
        self._image_path = config.FILES.ICONS.WARNING_L
        
        self.result: ClientDecision = ClientDecision.NONE

    def create_widgets(self):
        self.configure_window()

        frame_text = ttk.Frame(self._frame_main)
        frame_text.pack(expand=True, fill=tk.BOTH)

        try:
            image = ImageTk.PhotoImage(Image.open(self._image_path))
            label_image = ttk.Label(frame_text, image=image) # type: ignore
            label_image.image = image  # keep a reference! # type: ignore
            label_image.pack(side=tk.LEFT, padx=10, pady=10)
        except Exception:
            pass

        # Добавление виджетов внутрь ttk.Frame
        label_text = ttk.Label(frame_text, text=self._message, wraplength=250)
        label_text.pack(side=tk.LEFT, padx=10, pady=10)

        frame_buttom = ttk.Frame(self._frame_main)
        frame_buttom.pack()

        yes_button = ttk.Button(frame_buttom, text="Да", width=10, command=lambda: self.yes_no_result(ClientDecision.YES))
        yes_button.pack(side=tk.LEFT, padx=5, pady=5)
        no_button = ttk.Button(frame_buttom, text="Нет", width=10, command=lambda: self.yes_no_result(ClientDecision.NO))
        no_button.pack(side=tk.LEFT, padx=5, pady=5)
        
        self.bind("<Return>", lambda event: self.yes_no_result(ClientDecision.YES))
        self.bind("<Escape>", lambda event: self.yes_no_result(ClientDecision.NO))
    
    def configure_window(self):
        self.resizable(False, False)
        self.geometry('400x150')
        self.resizable(False, False)

        try:
            self.iconbitmap(self._icon_path)
        except tk.TclError:
            pass

        self._frame_main = ttk.Frame(self)
        self._frame_main.pack(expand=True, fill='both')

    def run(self) -> ClientDecision:
        self.create_widgets()
        # Захват ввода для модального окна
        self.grab_set()
        # Ограничение доступа к другим окнам до закрытия этого окна
        self.wait_window()

        return self.result

    def yes_no_result(self, result: ClientDecision):
        # Сохранение результата и закрытие диалога
        self.result = result
        self.destroy()

class YesNoDialog:
    @staticmethod
    def ask_yes_no(master: Any, title: str, message: str) -> ClientDecision:
        # Создаем и показываем конкретный тип сообщения
        return _YesNoDialog(master, title, message).run()

class PlaceholderVar(tk.StringVar):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.has_placeholder = False

    def set(self, value):
        if not self.has_placeholder:
            super().set(value)

    def get(self):
        if self.has_placeholder:
            return ""
        return super().get()
    
    def change_status(self, *args) -> None:
        self.has_placeholder = not self.has_placeholder

class PlaceholderEntry(ttk.Entry):
    """
    Класс для создания поля ввода с текстом-подсказкой (placeholder).
    Наследует от ttk.Entry.

    Параметры:
        master: родительский виджет, в который встраивается данный виджет.
        placeholder: строка, которая будет показываться в поле ввода как подсказка.
        color: цвет текста подсказки.
    """
    def __init__(self, master=None, placeholder="Введите текст...", color='grey', *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.placeholder = placeholder
        self.placeholder_color = color
        self.has_placeholder = tk.BooleanVar(value=False)  # Флаг для отслеживания, отображается ли placeholder

        textvariable = kwargs.get('textvariable', None)
        if textvariable is not None:
            if isinstance(textvariable, PlaceholderVar):
                self.has_placeholder.trace_add('write', textvariable.change_status)

        self.style = ttk.Style()
        self.default_fg_color = self.style.lookup('TEntry', 'foreground')
        self.default_bg_color = self.style.lookup('TEntry', 'background')

        # Привязываем события фокусировки на элемент и потери фокуса к обработчикам.
        self.bind("<FocusIn>", self._focus_in)
        self.bind("<FocusOut>", self._focus_out)
        self.bind("<<ThemeChanged>>", self._change_color)

        # Проверяем, содержит ли textvariable уже какой-то текст, если он передан.
        if 'textvariable' in kwargs and kwargs['textvariable'].get():
            self.configure(foreground=self.default_fg_color)
        else:
            self.put_placeholder()

    def put_placeholder(self):
        """Вставляет текст-подсказку в поле ввода и устанавливает цвет шрифта для подсказки."""
        self.delete(0, 'end')
        self.insert(0, self.placeholder)
        self.configure(foreground=self.placeholder_color)
        self.has_placeholder.set(True)

    def _focus_in(self, event):
        """
        Обработчик события получения фокуса полем ввода.
        Очищает поле, если в нем находится только текст-подсказка.

        Параметры:
            event: объект события, который содержит информацию о событии.
        """
        if self.has_placeholder.get():
            self.delete('0', 'end')
            self.configure(foreground=self.default_fg_color)
            self.has_placeholder.set(False)

    def _focus_out(self, event):
        """
        Обработчик события потери фокуса полем ввода.
        Вставляет текст-подсказку обратно, если поле осталось пустым.

        Параметры:
            event: объект события, который содержит информацию о событии.
        """
        if not self.get():  # Проверяем, пусто ли в поле.
            self.put_placeholder()  # Вставляем текст-подсказку, если поле пусто.

    def _change_color(self, *args):
        """
            Изменение цвета фона и текста виджетов в соответствии с темой.
        """
        if not self.has_placeholder:
            self.default_fg_color = self.style.lookup('TEntry', 'foreground')
            self.configure(foreground=self.default_fg_color)
        
            self.default_bg_color = self.style.lookup('TEntry', 'background')
            self.configure(background=self.default_bg_color)

class JustifiedCombobox(ttk.Combobox):
    """
    Настраиваемый виджет ttk.Combobox с динамической юстировкой элементов списка выбора.
    
    Параметры:
        master (Tkinter.Widget): Родительский виджет.
        **kwargs: Дополнительные параметры для настройки Combobox.

    Атрибуты:
        justify (str): Выравнивание элементов списка выбора.
        _master (Tkinter.Widget): Родительский виджет.
        _initial_bindtags (tuple): Исходные привязки к событиям Combobox.
        _dummy_tag (str): Уникальный тег для Combobox.
    """

    def __init__(self, master, **kwargs):
        """
        Инициализирует JustifiedCombobox.
        """
        ttk.Combobox.__init__(self, master, **kwargs)
        self.justify = 'center'
        self._master = master

    def _justify_popdown_list_text(self):
        """
        Юстирует текст в списке выбора.
        """
        self._initial_bindtags = self.bindtags()
        _bindtags = list(self._initial_bindtags)
        _index_of_class_tag = _bindtags.index(self.winfo_class())
        # Этот фиктивный тег должен быть уникальным для каждого объекта и не должен быть равен str(object)
        self._dummy_tag = '_' + str(self)
        _bindtags.insert(_index_of_class_tag + 1, self._dummy_tag)
        self.bindtags(tuple(_bindtags))
        _events_that_produce_popdown = tuple(['<KeyPress-Down>',
                                              '<ButtonPress-1>',
                                              '<Shift-ButtonPress-1>',
                                              '<Double-ButtonPress-1>',
                                              '<Triple-ButtonPress-1>',
                                              ])
        for _event_name in _events_that_produce_popdown:
            self.bind_class(self._dummy_tag, _event_name, self._initial_event_handle)

    def _initial_event_handle(self, event):
        """
        Обрабатывает начальные события.
        
        Параметры:
            event: Событие для обработки.
        """
        _instate = str(self['state'])
        if _instate != 'disabled':
            if event.keysym == 'Down':
                self._justify()
            else:
                _ = self.tk.eval('{} identify element {} {}'.format(self, event.x, event.y))
                __ = self.tk.eval('string match *textarea {}'.format(_))
                _is_click_in_entry = bool(int(__))
                if (_instate == 'readonly') or (not _is_click_in_entry):
                    self._justify()

    def _justify(self):
        """
        Юстирует список выбора.
        
        """
        self.tk.eval('{}.popdown.f.l configure -justify {}'.format(self, self.justify))
        self.bindtags(self._initial_bindtags)

    def __setattr__(self, name, value):
        """
        Устанавливает атрибут и юстирует список выбора, если атрибут - 'justify'.
        
        Параметры:
            name (str): Название атрибута для установки.
            value: Значение, которое будет установлено для атрибута.
        """
        self.__dict__[name] = value
        if name == 'justify':
            self._justify_popdown_list_text()

class Tooltip:
    """
    Создает всплывающую подсказку для виджета при наведении курсора мыши.
    
    Attributes:
        widget (tk.Widget): Виджет, к которому привязана подсказка.
        text (str): Текст всплывающей подсказки.
        delay (int): Задержка в миллисекундах перед показом подсказки.
        bg_color (str): Цвет фона подсказки.
        font (tuple): Шрифт текста подсказки.
    """
    def __init__(self, widget: tk.Widget, text: str,
                 delay: int = config.WIDGETS.TOOLTIP_SETTINGS.DELAY,
                 font: tuple = config.WIDGETS.TOOLTIP_SETTINGS.TEXT_FONT) -> None:
        self.master = widget
        self.text = text
        self.delay = delay
        self.font = font
        self.tip_window: Optional[tk.Toplevel] = None       # Окно всплывающей подсказки.
        self.id: str = ''                                   # Идентификатор задержки перед показом подсказки.
        self.master.bind("<Enter>", self.mouse_enter)
        self.master.bind("<Leave>", self.mouse_leave)

    def mouse_enter(self, event: Optional[tk.Event] = None) -> None:
        """Обработка ивента наведения мыши на виджет."""
        self.schedule()

    def mouse_leave(self, event: Optional[tk.Event] = None) -> None:
        """Обработка ивента отведения мыши от виджета."""
        self.unschedule()
        self.hide_tip()

    def schedule(self) -> None:
        """Планирует показ подсказки с задержкой."""
        self.unschedule()
        self.id = self.master.after(self.delay, self.show_tip)

    def unschedule(self) -> None:
        """Отменяет запланированное событие, если оно есть."""
        id = self.id
        self.id = ""
        if id:
            self.master.after_cancel(id)

    def show_tip(self, event: Optional[tk.Event] = None) -> None:
        """Отображает подсказку в вычисленной позиции."""
        x, y, cx, cy = self.master.bbox("insert") # type: ignore
        x += self.master.winfo_rootx() + 25
        y += self.master.winfo_rooty() + 20
        self.tip_window = tw = tk.Toplevel(self.master)
        tw.wm_overrideredirect(True)
        tw.wm_geometry("+%d+%d" % (x, y))

        label = ttk.Label(tw, text=self.text, justify=tk.LEFT,
                           relief=tk.SOLID, borderwidth=1, font=self.font)
        label.pack(ipadx=1)

    def hide_tip(self) -> None:
        """Скрывает подсказку, если она отображается."""
        tw = self.tip_window
        self.tip_window = None
        if tw:
            tw.destroy()


class LimitedText(ttk.Frame):
    def __init__(self, master: Any, max_size: int, **kwargs) -> None:
        """
            Инициализация компонента с ограниченным текстовым полем.

        Args:
            master: Родительский виджет.
            max_size: Максимальное количество символов.
            **kwargs: Дополнительные аргументы ttk.Frame.
        """
        super().__init__(master, **kwargs)

        self._master = master
        self._max_size = max_size

        self._text_input_message = tk.Text(self, height=4, font=config.WIDGETS.INPUT_TEXT_FONT) # type: ignore
        self._progressbar = ttk.Progressbar(self, mode='determinate', maximum=max_size, value=0)

        self._text_input_message.pack(fill='x', padx=5, pady=5)
        self._progressbar.pack(fill='x', padx=5)

        self._text_input_message.bind('<Key>', self._check_limit)
        self._text_input_message.bind('<Control-v>', self._handle_paste)
        self._text_input_message.bind('<KeyRelease>', self._update_progress)

    def _check_limit(self, event) -> None:
        """
            Проверка лимита символов при нажатии клавиши.

        Args:
            event: Событие нажатия клавиши.
        """
        # Получаем текущее содержимое виджета
        current_text = self._text_input_message.get('1.0', 'end-1c')

        # Разрешаем нажатие Backspace, Delete, стрелок, и пропускаем управляющие символы 
        # и события без символов (например, Shift)
        if (event.keysym in ('BackSpace', 'Delete', 'Left', 'Right', 'Up', 'Down') 
            or event.char in ('\x08', '\x7f') or not event.char):
            return

        # Проверяем длину текста с учетом возможного нового символа
        if len(current_text) >= self._max_size:
            return 'break' # type: ignore

    def _handle_paste(self, event=None) -> str:
        """
            Обработка вставки текста из буфера обмена.

        Args:
            event: Событие вставки.
        """
        try:
            clipboard_text = self._text_input_message.clipboard_get()
        except tk.TclError:
            return 'break'  # Если в буфере обмена нет текста
        
        current_text = self._text_input_message.get('1.0', 'end-1c')
        selection = self._text_input_message.tag_ranges(tk.SEL)
        if selection:
            selected_text = self._text_input_message.get(*selection)
            # Рассчитываем длину текста после возможной вставки с учетом замены выделенного текста
            current_length = len(current_text) - len(selected_text)
        else:
            current_length = len(current_text)
        
        max_paste_length = self._max_size - current_length
        paste_text = clipboard_text[:max_paste_length]  # Обрезаем текст до максимально допустимой длины
        
        if selection:
            self._text_input_message.delete(*selection)  # Удаляем выделенный текст, если таковой имеется
        
        self._text_input_message.insert(tk.INSERT, paste_text)
        return 'break'  # Предотвращаем дальнейшую обработку события (вставку)

    def _update_progress(self, event=None) -> None:
        """
            Обновление индикатора заполнения.
        """
        current_text_length = len(self._text_input_message.get('1.0', 'end-1c'))
        self._progressbar['value'] = current_text_length

    def get_text(self) -> str:
        """
            Возвращает текст из текстового поля.

        Returns:
            Строка текста.
        """
        return self._text_input_message.get("1.0", tk.END)
    
    def del_text(self) -> None:
        """
            Очищает текстовое поле и обновляет индикатор заполнения.
        """
        self._text_input_message.delete("1.0", tk.END)
        self._update_progress()

    def activate(self) -> None:
        """
            Делает текстовое поле активным для ввода.
        """
        self._text_input_message.config(state='normal')

    def inactivate(self) -> None:
        """
            Делает текстовое поле неактивным для ввода.
        """
        self._text_input_message.config(state='disabled')
    
class Dialog(ttk.Frame):
    objects_counter = 0 # Счетчик объектов класса для присвоения уникальных ID

    def __init__(self, master: Any, interlocutor_id: str, username: str = '',
                  dialog_name: str = '', command: Any = None, **kwargs) -> None:
        """
            Инициализация диалогового окна.

        Args:
            master: Родительский виджет.
            interlocutor_id: ID собеседника.
            username: Имя пользователя. Если None, будет сгенерировано случайное имя.
            dialog_name: Название диалога. Если None, будет сгенерировано случайное название.
            command: Функция обратного вызова для обработки отправленных сообщений.
            **kwargs: Дополнительные аргументы для ttk.Frame.
        """
        super().__init__(master, **kwargs)

        self._master = master
        self._interlocutor_id = interlocutor_id
        self._username = username if username else self._generate_random_name()
        self._command = command

        self._moscow_tz = pytz.timezone('Europe/Moscow')
        
        self._dialog_name = dialog_name if dialog_name else self._generate_random_name()
        self._id = Dialog.objects_counter
        Dialog.objects_counter += 1

        self._messages: List[MessageTextData] = []  # Список сообщений в диалоге
        self._message_id_counter = 0  # Счетчик ID сообщений

        self._setup_widgets()  # Метод установки виджетов
        self._bind_events()  # Метод привязки событий
   
    def _setup_widgets(self) -> None:
        """
            Настройка виджетов диалогового окна.
        """
        self._frame_dialog = ttk.Frame(self)
        self._text_dialog = tk.Text(self._frame_dialog, state='disabled', height=20, font=config.WIDGETS.DIALOG_TEXT_FONT) # type: ignore
        self._scrollbar = tk.Scrollbar(self._frame_dialog, command=self._text_dialog.yview)
        self._frame_input = LimitedText(self, config.WIDGETS.MAX_TEXT_SYMBOLS_NUMBER)
        self._button_send_input_message = ttk.Button(self, text="Отправить", command=self.send_message)

        self._frame_dialog.pack(fill='both', expand=True)
        self._text_dialog.pack(side=tk.LEFT, fill='both', expand=True, padx=5, pady=5)
        self._scrollbar.pack(side=tk.LEFT, fill=tk.Y)
        self._frame_input.pack(fill='both', expand=True)
        self._button_send_input_message.pack(fill='both', expand=True, padx=5)

        self._text_dialog.config(yscrollcommand=self._scrollbar.set)
        self._text_dialog.tag_configure("bold", font=config.WIDGETS.DIALOG_AUTHOR_FONT) # type: ignore

    def _bind_events(self):
        """
            Привязка событий к виджетам.
        """
        self._master.bind("<<ThemeChanged>>", self._change_color)
        # Привязка события перетаскивания файла в текстовое поле
        self._text_dialog.drop_target_register(DND_FILES) # type: ignore
        self._text_dialog.dnd_bind('<<Drop>>', self._drag_n_drop_event_handler) # type: ignore

    def _drag_n_drop_event_handler(self, event):
        """
            Обрабатывает перетаскивание файлов в текстовое поле, проверяя их и отправляя данные файла.

            При успешном перетаскивании файла (или файлов) в текстовое поле, данный метод
            читает файл, проверяет его размер и, если все условия соблюдены, передает данные файла
            в пользовательскую функцию обратного вызова (_command).

        Args:
            event: Событие перетаскивания файла.
        """
        # Проверяем, активна ли кнопка "Отправить"
        if self._button_send_input_message['state'] == 'disabled':
            return


        def __send_files(files: list[FilenameType]):
            for file in files:
                # Проверяем, является ли путь файлом
                if not os.path.isfile(file):
                    CustomMessageBox.show(self._master, 'Ошибка', f'Можно передавать только файлы!', CustomMessageType.ERROR)
                    continue

                if os.path.getsize(file) > config.WIDGETS.MAX_FILE_SIZE:
                    CustomMessageBox.show(self._master, 'Ошибка', f'Слишком большой файл [{file}]!\nМаксимальный размер: {config.WIDGETS.MAX_FILE_SIZE} байт.', CustomMessageType.ERROR)
                    continue

                # Если размер файла не превышает максимально допустимый, отправляем данные
                # Читаем данные файла
                with open(file, 'rb') as bin_file:
                    file_data: bytes = bin_file.read(config.WIDGETS.MAX_FILE_SIZE)
                        
                    try:
                        self._command(MessageData(
                            type    = MessageType.File,
                            message = MessageFileData(
                                raw_data = base64.b64encode(file_data).decode('utf-8'),
                                filename = os.path.basename(file)
                            )
                        ))
                    except Exception as e:
                        CustomMessageBox.show(self._master, 'Ошибка', f'Произошла ошибка [{e}]!', CustomMessageType.ERROR)

        # Разбиваем данные события на список путей к файлам
        files = self.tk.splitlist(event.data)
        threading.Thread(target=__send_files, args=(files, ), daemon=True).start()

    def _change_color(self, *args):
        """
            Изменение цвета фона и текста виджетов в соответствии с темой.
        """
        _style = ttk.Style()
        bg_color = _style.lookup('TFrame', 'background')
        fg_color = _style.lookup('TLabel', 'foreground')
        self._frame_input._text_input_message.config(bg=bg_color, fg=fg_color)
        self._text_dialog.config(bg=bg_color, fg=fg_color)

    def send_message(self) -> None:
        """
            Отправляет сообщение, указанное пользователем, и обновляет интерфейс диалога.
        """
        # Получаем текст из Text widget
        message = self._frame_input.get_text().strip()
        
        # Если сообщение не пустое, обрабатываем его
        if message:
            # Фиксируем текущее время в московском часовом поясе
            current_time = datetime.now(self._moscow_tz)
            
            # Добавляем сообщение в историю сообщений
            self._messages.append(MessageTextData(
                id      = f'm{self._message_id_counter}',
                time    = current_time.isoformat(),
                author  = self._username,
                message = message
            ))
            self._message_id_counter += 1

            # Форматируем сообщение для отображения в диалоге
            formatted_message = self._format_message(self._messages[-1], current_time)
            self._add_message_to_dialog(formatted_message, formatted_message.index(': ') + 1)
            
            # Очищаем поле ввода после отправки сообщения
            self._frame_input.del_text()

            # Вызов пользовательской функции, если она задана
            if self._command:
                self._command(MessageData(
                    type    = MessageType.Text,
                    message = self._messages[-1]
                ))
    
    def exist_message(self, message: MessageTextData) -> bool:
        """
            Проверяет, существует ли сообщение с указанным ID в истории диалога.

        Args:
            message: Объект класса MessageTextData.

        Returns:
            True, если сообщение существует, иначе False.
        """
        for msg in self._messages:
            if msg.id == message.id:
                return True
        return False

    def recieve_message(self, message: MessageTextData) -> None:
        """
            Обрабатывает получение сообщения и обновляет интерфейс диалога.

        Args:
            message: Объект класса MessageTextData.
        """

        if message:
            recived_message_time = datetime.fromisoformat(message.time)

            # Обновляем счетчик ID сообщений, если необходимо
            self._update_counter(message.id)

            # Если в истории уже есть сообщения, проверяем порядок времени получения
            if self._messages and recived_message_time < datetime.fromisoformat(self._messages[-1].time):
                # Перестраиваем историю сообщений, если полученное сообщение старше последнего
                self._restruct_dialog_messages(message)
                return

            # Просто добавляем сообщение в диалог
            formatted_message = self._format_message(message, recived_message_time)
            self._add_message_to_dialog(formatted_message, formatted_message.index(': ') + 1)

            self._messages.append(message)
            # Сортируем сообщения по времени, на случай если порядок был нарушен
            self._messages.sort(key=lambda x: x.time)

    def load_history(self, history: List[MessageTextData]) -> None:
        """
            Загружает историю сообщений в диалог.

        Args:
            history: Список объектов MessageTextData.
        """
        if not history:
            return

        # Сортировка истории по времени
        history = sorted(history, key=lambda x: datetime.fromisoformat(x.time))

        messages_size_before = len(self._messages)
        # Интеграция каждого сообщения из истории
        for message in history:
            if self.exist_message(message):
                continue

            self._update_counter(message.id)
            
            message_time = datetime.fromisoformat(message.time)
            formatted_message = self._format_message(message, message_time)
            self._add_message_to_dialog(formatted_message, formatted_message.index(': ') + 1)
            self._messages.append(message)

        if messages_size_before != len(self._messages):
            self._messages.sort(key=lambda x: datetime.fromisoformat(x.time))

    def _update_counter(self, msg_id: MessageIdType) -> None:
        """
        Обновляет счётчик сообщений на основе идентификатора сообщения.

        Args:
            msg_id: Идентификатор сообщения.
        """
        if 'm' in msg_id:
            counter = int(msg_id.replace('m', ''))
            if self._message_id_counter <= counter:
                self._message_id_counter = counter + 1

    def _format_message(self, message: MessageTextData, message_time: datetime) -> str:
        """
        Форматирует сообщение для вывода.

        Args:
            message: Объект MessageTextData.
            message_time: Время сообщения.

        Returns:
            Отформатированное сообщение.
        """
        return f"[{message_time.strftime('%d.%m.%Y - %H:%M:%S')}] {message.author}: {message.message}\n"


    def _restruct_dialog_messages(self, recv_message: MessageTextData) -> None:
        """
            Вставляет полученное сообщение в хронологически правильное место в диалоге.

        Args:
            recv_message: Полученное сообщение типа MessageTextData.
        """
        # Инициализация переменных для отслеживания позиции вставки
        counter = 0
        pos_in_text = 1
        was_inserted = False

        # Преобразование строки времени в объект datetime
        received_message_time = datetime.fromisoformat(recv_message.time)

        # Перебор существующих сообщений для поиска подходящего места вставки
        for message in self._messages:
            message_time = datetime.fromisoformat(message.time)

            # Вставка, если время полученного сообщения меньше времени текущего сообщения в списке
            if received_message_time < message_time and not was_inserted:
                formatted_message = self._format_message(recv_message, received_message_time)
                self._add_message_to_dialog(formatted_message, formatted_message.index(': ') + 1, pos_in_text)
                was_inserted = True
                break   

            if not was_inserted:
                counter += 1
                pos_in_text += message.message.count('\n') + 1
        
        # Вставка сообщения в список сообщений
        self._messages.insert(counter, recv_message)


    def _add_message_to_dialog(self, formatted_message: str, date_and_author_len: int, pos: int = -1) -> None:
        """
            Добавляет форматированное сообщение в виджет текстового диалога.

        Args:
            formatted_message: Отформатированное сообщение.
            date_and_author_len: Длина строки с датой и автором.
            pos: Позиция вставки в виджете.
        """
        
        # Получаем номер следующей строки
        next_line_number = int(self._text_dialog.index("end-1c").split(".")[0]) if pos == -1 else pos

        # Добавляем сообщение в конец
        self._text_dialog.config(state='normal')
        self._text_dialog.insert(f"{next_line_number}.0", formatted_message)
        self._text_dialog.tag_add("bold", f"{next_line_number}.0", f"{next_line_number}.{date_and_author_len}")
        self._text_dialog.config(state='disabled')

        # Прокрутка к последней добавленной строке
        self._text_dialog.see(tk.END)

    def _generate_random_name(self) -> str:
        """
            Генерирует случайное имя пользователя.

        Returns:
            Строка, содержащая случайное имя пользователя.
        """
        # Строка со всеми буквами и цифрами
        characters = string.ascii_letters + string.digits
        # Выбор случайных символов из строки characters
        return ''.join(random.choice(characters) for _ in range(12))
    
    def get_id(self) -> int:
        """
            Получает уникальный идентификатор диалога.

        Returns:
            Идентификатор диалога.
        """
        return self._id
    
    def get_interlocutor_id(self) -> str:
        """
            Получает идентификатор собеседника.

        Returns:
            Идентификатор собеседника.
        """
        return self._interlocutor_id

    def activate(self) -> None:
        """
            Активирует элементы управления диалогом.
        """
        self._frame_input.activate()
        self._button_send_input_message.config(state='normal')

    def inactivate(self) -> None:
        """
            Деактивирует элементы управления диалогом.
        """
        self._frame_input.inactivate()
        self._button_send_input_message.config(state='disabled')


class UnavailableDialogIdError(Exception):
    """Исключение, возникающее при вводе некорректного идентификатора диалога."""

    def __init__(self, message="Введен некорректный идентификатор диалога."):
        self.message = message
        super().__init__(self.message)

class EmptyActiveDialogError(Exception):
    """Исключение, возникающее при попытке получить пустой активный диалог."""

    def __init__(self, message="Попытка получения пустого активного диалога."):
        self.message = message
        super().__init__(self.message)


class DialogInfo(NamedTuple):
    tab_id: int
    dialog: Dialog

class DialogManager(ttk.Frame):
    def __init__(self, master: Any, username: str = '', command: Any = None, **kwargs) -> None:
        """
            Инициализирует менеджер диалогов, наследующийся от ttk.Frame.

        Args:
            master: Родительский виджет.
            username: Имя пользователя.
            command: Команда, выполняемая при определенных действиях.
            kwargs: Дополнительные параметры для ttk.Frame.
        """
        super().__init__(master, **kwargs)

        self._master: Any = master
        self._username: str = username
        self._command: Any = command
        self._dialogs: dict[int, DialogInfo] = {}
        self._hidden_tabs: dict[int, tuple[Any, str]] = {}

        self._right_click_handler: Any = None
        self._middle_click_handler: Any = None

        # Создание виджета Notebook
        self._notebook_dialogs = ttk.Notebook(self)
        self._notebook_dialogs.pack(expand=True, fill='both', padx=10, pady=10)

        _right_click = '<Button-3>' if platform.system() != 'Darwin' else '<Button-2>' # Если не макось
        _middle_click = '<Button-2>' if platform.system() != 'Darwin' else '<Button-3>' # Если не макось
        self._notebook_dialogs.bind(_right_click, self._handle_right_click)
        self._notebook_dialogs.bind(_middle_click, self._handle_middle_click)

    def add_right_click_handler(self, handler: Callable) -> None:
        """
            Добавляем функцию-обработчик для события нажатия правой кнопкой мыши на вкладку.
        
        Args:
            handler (Callable): функция-обработчик
        """
        self._right_click_handler = handler

    def add_middle_click_handler(self, handler: Callable) -> None:
        """
            Добавляем функцию-обработчик для события нажатия центральной кнопкой мыши на вкладку.
        
        Args:
            handler (Callable): функция-обработчик
        """
        self._middle_click_handler = handler

    def __handle_click(self, event: Any) -> Union[Dialog, None]:
        """
            Обрабатываем события нажатия на вкладку.

        Args:
            event (Any): Событие

        Returns:
            Диалог нажатой вкладки.
        """ 
        element = self._notebook_dialogs.identify(event.x, event.y)
        if "label" in element:
            index = self._notebook_dialogs.index("@{},{}".format(event.x, event.y))
            return self._notebook_dialogs.nametowidget(self._notebook_dialogs.tabs()[index])
        return None

    def _handle_right_click(self, event) -> None:
        """
            Обрабатываем события нажатия правой кнопкой мыши на вкладку.

        Args:
            event (Any): Событие
        """
        widget = self.__handle_click(event)
        if widget is not None:
            dialog: Dialog = widget
            self._right_click_handler(dialog.get_interlocutor_id())
            self.inactivate_dialog(dialog.get_id())

    def _handle_middle_click(self, event) -> None:
        """
            Обрабатываем события нажатия центральной кнопкой мыши на вкладку.

        Args:
            event (Any): Событие
        """
        widget = self.__handle_click(event)
        if widget is not None:
            dialog: Dialog = widget
            self._middle_click_handler(dialog.get_interlocutor_id())
            self.hide_dialog(dialog.get_id())

    def set_username(self, username: str) -> None:
        """
            Устанавливает или обновляет имя пользователя.

        Args:
            username: Новое имя пользователя.
        """
        self._username = username

    def add_dialog(self, dialog_name: str, interlocutor_id: str, dialog_history: List[MessageTextData]) -> int:
        """
            Добавляет новую вкладку диалога в Notebook.

        Args:
            dialog_name: Название диалога.
            interlocutor_id: Идентификатор собеседника.
            dialog_history: История сообщений диалога.

        Returns:
            Идентификатор созданного диалога.
        """
        # Создание новой вкладки с CustomWidget
        dialog = Dialog(
            master          = self._notebook_dialogs,
            interlocutor_id = interlocutor_id,
            username        = self._username,
            dialog_name     = dialog_name,
            command         = self._command
        )

        self._dialogs[dialog.get_id()] = DialogInfo(tab_id=self._notebook_dialogs.index('end'), dialog=dialog)
        dialog.load_history(dialog_history)

        dialog.pack(expand=True, fill='both')
        self._notebook_dialogs.add(dialog, text=f"{dialog_name}")
        self._notebook_dialogs.select(self._notebook_dialogs.index('end') - 1)

        return dialog.get_id()

    def inactivate_dialog(self, dialog_id: int) -> None:
        """
            Деактивирует указанный диалог.

        Args:
            dialog_id: Идентификатор диалога.
        """
        if dialog_id in self._dialogs:
            self._dialogs[dialog_id].dialog.inactivate()

    def hide_dialog(self, dialog_id: int) -> None:
        """
            Скрывает указанный диалог из интерфейса.

        Args:
            dialog_id: Идентификатор диалога.
        """
        if dialog_id in self._dialogs:
            self._hidden_tabs.update({
                self._dialogs[dialog_id].tab_id: (
                    self._notebook_dialogs.tabs()[self._dialogs[dialog_id].tab_id],
                    self._notebook_dialogs.tab(self._dialogs[dialog_id].tab_id, 'text'),
                )
            })
            self._notebook_dialogs.hide(self._dialogs[dialog_id].tab_id)
        
    def load_dialog(self, dialog_id: int) -> None:
        """
            Загружает и активирует указанный диалог.

        Args:
            dialog_id: Идентификатор диалога.
        """
        if dialog_id in self._dialogs:
            if self._dialogs[dialog_id].tab_id in self._hidden_tabs:
                tab, text = self._hidden_tabs[self._dialogs[dialog_id].tab_id]
                self._notebook_dialogs.add(tab, text=text)
                self._notebook_dialogs.select(tab)

                del self._hidden_tabs[self._dialogs[dialog_id].tab_id]

            self._dialogs[dialog_id].dialog.activate()

    def close_all(self) -> None:
        """
            Скрывает все диалоги из интерфейса и удаляет их данные из памяти.
        """
        for _, dialog_info in self._dialogs.items():
            self._notebook_dialogs.hide(dialog_info.tab_id)
        self._dialogs = {}
        self._hidden_tabs = {}

    def size(self) -> int:
        """
            Возвращает количество диалогов.

        Returns:
            Количество диалогов.
        """
        return len(self._dialogs)
    
    def get_dialog(self, dialog_id: int) -> Dialog:
        """
            Возвращает объект диалога по его идентификатору.

        Args:
            dialog_id: Идентификатор диалога.

        Returns:
            Объект диалога.
        
        Raises:
            UnavailableDialogIdError: Если введен некорректный id диалога.
        """
        if dialog_id not in self._dialogs:
            raise UnavailableDialogIdError
        return self._dialogs[dialog_id].dialog
    
    def get_current_dialog(self) -> Dialog:
        """
            Возвращает текущий активный диалог.

        Returns:
            Активный диалог.

        Raises:
            EmptyActiveDialogError: Если нет активного диалога.
        """
        try:
            current_tab = self._notebook_dialogs.select()
            widget = self.nametowidget(current_tab)
            return widget
        except Exception:
            raise EmptyActiveDialogError('Нет активного диалога для получения.')