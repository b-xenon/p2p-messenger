import os
import tkinter as tk
from tkinter import ttk
from tkinterdnd2 import DND_FILES

import random
import string

import base64
import enum
import pyperclip
from PIL import Image, ImageTk

import pytz
from datetime import datetime

from config import MAX_TEXT_SYMBOLS_NUMBER, paths, MAX_FILE_SIZE
from libs.network import MessageDataType

class MessageType(enum.Enum):
    ANY = 'ANY'
    INFO = 'INFO'
    WARNING = 'WARNING'
    ERROR = 'ERROR'
    SUCCESS = 'SUCCESS'

class MessageBox(tk.Toplevel):
    def __init__(self, master, title, message, message_type=MessageType.ANY):
        super().__init__(master)
        self.title(title)
        self.message = message
        self.message_type = message_type

        # Это должно быть переопределено в подклассах
        self.icon_path = paths["files"]["icon"]["main"]
        self.image_path = paths["files"]["icon"]["info_l"]

    def create_widgets(self):
        self.configure_window()
        self.create_message_frame()
        self.create_buttons_frame()

    def configure_window(self):
        self.resizable(False, False)
        self.geometry(self.calculate_geometry())

        try:
            self.iconbitmap(self.icon_path)
        except tk.TclError:
            pass

        self.frame_main = ttk.Frame(self)
        self.frame_main.pack(expand=True, fill='both')

    def calculate_geometry(self, width=360, height=150):
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = (screen_width - width + random.randint(-50, 50)) // 2
        y = (screen_height - height + random.randint(-50, 50)) // 2
        return f'{width}x{height}+{x}+{y}'

    def create_message_frame(self):
        frame = ttk.Frame(self.frame_main)
        frame.pack(expand=True, fill=tk.BOTH)

        image = ImageTk.PhotoImage(Image.open(self.image_path))
        label_image = ttk.Label(frame, image=image)
        label_image.image = image  # keep a reference!
        label_image.pack(side=tk.LEFT, padx=10, pady=10)

        label_text = ttk.Label(frame, text=self.message, wraplength=250)
        label_text.pack(side=tk.LEFT, padx=10, pady=10)

    def create_buttons_frame(self):
        frame = ttk.Frame(self.frame_main)
        frame.pack()

        button_ok = ttk.Button(frame, text="OK", command=self.destroy)
        button_ok.pack(side=tk.LEFT, padx=10, pady=10)

        button_copy = ttk.Button(frame, text="Копировать", command=self.copy_text)
        button_copy.pack(side=tk.LEFT, padx=10, pady=10)

    def copy_text(self):
        pyperclip.copy(self.message)

class CustomMessageBox:
    @staticmethod
    def show(master, title, message, message_type=MessageType.ANY):
        if message_type == MessageType.INFO:
            icon = paths["files"]["icon"]["info_l"]
        elif message_type == MessageType.WARNING:
            icon = paths["files"]["icon"]["warning_l"]
        elif message_type == MessageType.ERROR:
            icon = paths["files"]["icon"]["error_l"]
        elif message_type == MessageType.SUCCESS:
            icon = paths["files"]["icon"]["success_l"]
        else:
            icon = paths["files"]["icon"]["main"]

        # Создаем и показываем конкретный тип сообщения
        message_box = MessageBox(master, title, message, message_type)
        message_box.icon_path = paths["files"]["icon"]["main"]
        message_box.image_path = icon
        message_box.create_widgets()


class LimitedText(ttk.Frame):
    def __init__(self, master, max_size, **kwargs) -> None:
        super().__init__(master, **kwargs)

        self._master = master
        self._max_size = max_size

        self._text_input_message = tk.Text(self, height=4, font=('Calibri', 10))
        self._progressbar = ttk.Progressbar(self, mode='determinate', maximum=max_size, value=0)

        self._text_input_message.pack(fill='x', padx=5, pady=5)
        self._progressbar.pack(fill='x', padx=5)

        self._text_input_message.bind('<Key>', self._check_limit)
        self._text_input_message.bind('<Control-v>', self._handle_paste)
        self._text_input_message.bind('<KeyRelease>', self._update_progress)

    def _check_limit(self, event):
        # Получаем текущее содержимое виджета
        current_text = self._text_input_message.get('1.0', 'end-1c')

        # Разрешаем нажатие Backspace, Delete, стрелок, и пропускаем управляющие символы и события без символов (например, Shift)
        if event.keysym in ('BackSpace', 'Delete', 'Left', 'Right', 'Up', 'Down') or event.char in ('\x08', '\x7f') or not event.char:
            return

        # Проверяем длину текста с учетом возможного нового символа
        if len(current_text) >= self._max_size:
            return 'break'

    def _handle_paste(self, event):
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

    def _update_progress(self, event=None):
        current_text_length = len(self._text_input_message.get('1.0', 'end-1c'))
        self._progressbar['value'] = current_text_length

    def get_text(self) -> str:
        return self._text_input_message.get("1.0", tk.END)
    
    def del_text(self) -> None:
        self._text_input_message.delete("1.0", tk.END)
        self._update_progress()

    def activate(self) -> None:
        self._text_input_message.config(state='normal')

    def inactivate(self) -> None:
        self._text_input_message.config(state='disabled')



class Dialog(ttk.Frame):
    objects_counter = 0

    def __init__(self, master, interlocutor_id, username=None, dialog_name=None, command=None, **kwargs) -> None:
        super().__init__(master, **kwargs)

        self._master = master
        self._interlocutor_id = interlocutor_id
        self._username = username if username is not None else self._generate_random_name()
        self._command = command

        self._moscow_tz = pytz.timezone('Europe/Moscow')
        
        self._dialog_name = dialog_name if dialog_name is not None else self._generate_random_name()
        self._id = Dialog.objects_counter
        Dialog.objects_counter += 1

        # {'author': None, 'msg': None, 'msg_id': None, 'time': None }
        self._messages = []
        self._message_id_counter = 0

        # Создание виджетов Text и Button
        self._frame_dialog = ttk.Frame(self)
        self._text_dialog = tk.Text(self._frame_dialog, state='disabled', height=20, font=('Calibri', 10))
        self._scrollbar = tk.Scrollbar(self._frame_dialog, command=self._text_dialog.yview)
        
        self._frame_input = LimitedText(self, MAX_TEXT_SYMBOLS_NUMBER)

        self._button_send_input_message = ttk.Button(self, text="Отправить", command=self.send_message)
        
        # Определяем тег для жирного шрифта
        self._text_dialog.tag_configure("bold", font=('Calibri', 10, 'bold'))

        # Размещение виджетов в окне
        self._frame_dialog.pack(fill='both', expand=True)
        self._text_dialog.pack(side=tk.LEFT, fill='both', expand=True, padx=5, pady=5)
        self._scrollbar.pack(side=tk.LEFT, fill=tk.Y)

        self._frame_input.pack(fill='both', expand=True)

        self._button_send_input_message.pack(fill='both', expand=True, padx=5)

        # Настраиваем виджет Text для работы со Scrollbar
        self._text_dialog.config(yscrollcommand=self._scrollbar.set)

        self._change_color()
        self._master.bind("<<ThemeChanged>>", self._change_color)

        # register the listbox as a drop target
        self._text_dialog.drop_target_register(DND_FILES)
        self._text_dialog.dnd_bind('<<Drop>>', self._drag_n_drop_event_handler)
   
    def _drag_n_drop_event_handler(self, event):
        if self._button_send_input_message['state'] == 'disabled':
            return

        files = self.tk.splitlist(event.data)
        for f in files:
            if not os.path.isfile(f):
                CustomMessageBox.show(self._master, 'Ошибка', f'Можно передавать только файлы!', MessageType.ERROR)
                continue
            with open(f'{f}', 'rb') as file:
                file_data = b''
                _eof = False
                while not _eof:
                    _data = file.read(1024)
                    
                    if not _data:
                        _eof = True
                    
                    file_data += _data
                    if len(file_data) > MAX_FILE_SIZE:
                        CustomMessageBox.show(self._master, 'Ошибка', f'Слишком большой файл! Максимальный размер [{MAX_FILE_SIZE}]!', MessageType.ERROR)
                        break
                else:
                    try:
                        self._command({'data': {'raw_data': base64.b64encode(file_data).decode('utf-8'), 'filename': os.path.basename(f)}, 'type': MessageDataType.File})
                    except Exception as e:
                        pass

    def _change_color(self, *args):
        _style = ttk.Style()
        bg_color = _style.lookup('TFrame', 'background')
        fg_color = _style.lookup('TLabel', 'foreground')

        self._frame_input._text_input_message.config(bg=bg_color, fg=fg_color)
        self._text_dialog.config(bg=bg_color, fg=fg_color)

    def send_message(self) -> None:
        # Получаем текст из Text widget
        message = self._frame_input.get_text().strip()
        
        if message:  # Проверяем, что текст не пустой
            current_time = datetime.now(self._moscow_tz)

            formatted_message = f"[{current_time.strftime('%d.%m.%Y - %H:%M:%S')}] {self._username}: {message}\n"
            self._add_message_to_dialog(formatted_message, len(formatted_message.split(': ')[0]) + 1)

            # Очищаем Text widget
            self._frame_input.del_text()
        
            self._messages.append({
                'author': self._username,
                'msg': message,
                'msg_id': f'm{self._message_id_counter}',
                'time': current_time.isoformat()
            })
            self._message_id_counter += 1

            # Вызов пользовательской функции, если она задана
            if self._command:
                self._command({'data': self._messages[-1], 'type': MessageDataType.Text})
    
    def exist_message(self, message: dict) -> bool:
        for msg in self._messages:
            if msg['msg_id'] == message['msg_id']:
                return True
        return False

    def recieve_message(self, message: dict) -> None:
        if message:
            recived_message_time = datetime.fromisoformat(message['time'])

            if 'm' in message['msg_id']:
                c = int(message['msg_id'].replace('m', ''))
                if self._message_id_counter < c:
                    self._message_id_counter = c + 1

            if len(self._messages):
                last_my_message_time = datetime.fromisoformat(self._messages[-1]['time'])

                if recived_message_time < last_my_message_time:
                    self._restruct_dialog_messages(message)
                    return

            formatted_message = f"[{recived_message_time.strftime('%d.%m.%Y - %H:%M:%S')}] {message['author']}: {message['msg']}\n"
            self._add_message_to_dialog(formatted_message, len(formatted_message.split(': ')[0]) + 1)

            self._messages.append(message)
            self._messages.sort(key=lambda x: x['time'])

    def load_history(self, history: list[dict]):
        if history:
            history = sorted(history, key=lambda x: x['time'])
            if not self._messages:
                self._messages.sort(key=lambda x: x['time'])

            counter = self._message_id_counter
            for message in history:
                message_time = datetime.fromisoformat(message['time'])

                if 'm' in message['msg_id']:
                    c = int(message['msg_id'].replace('m', ''))
                    if counter < c:
                        counter = c

                formatted_message = f"[{message_time.strftime('%d.%m.%Y - %H:%M:%S')}] {message['author']}: {message['msg']}\n"
                self._add_message_to_dialog(formatted_message, len(formatted_message.split(': ')[0]) + 1)

                self._messages.append(message)
            
            if self._message_id_counter != counter:
                self._message_id_counter = counter + 1

    def _restruct_dialog_messages(self, recv_message: dict) -> None:
        counter = 0
        pos_in_text = 1
        was_inserted = False
        recived_message_time = datetime.fromisoformat(recv_message['time'])
        for message in self._messages:
            message_time = datetime.fromisoformat(message['time'])

            if recived_message_time < message_time:
                if not was_inserted:
                    was_inserted = True
                    formatted_message = f"[{recived_message_time.strftime('%d.%m.%Y - %H:%M:%S')}] {recv_message['author']}: {recv_message['msg']}\n"
                    self._add_message_to_dialog(formatted_message, len(formatted_message.split(':')[0]) + 1, pos_in_text)
                    break

            if not was_inserted:
                counter += 1
                pos_in_text += message['msg'].count('\n') + 1
        
        self._messages.insert(counter, recv_message)


    def _add_message_to_dialog(self, formatted_message: str, date_and_author_len: int, pos: int = None) -> None:
        # Получаем номер следующей строки
        next_line_number = int(self._text_dialog.index("end-1c").split(".")[0]) if pos is None else pos

        # Добавляем сообщение в конец
        self._text_dialog.config(state='normal')
        self._text_dialog.insert(f"{next_line_number}.0", formatted_message)
        self._text_dialog.tag_add("bold", f"{next_line_number}.0", f"{next_line_number}.{date_and_author_len}")
        self._text_dialog.config(state='disabled')

        # Прокрутка к последней добавленной строке
        self._text_dialog.see(tk.END)

    def _generate_random_name(self) -> str:
        # Строка со всеми буквами и цифрами
        characters = string.ascii_letters + string.digits
        # Выбор случайных символов из строки characters
        random_string = ''.join(random.choice(characters) for i in range(12))
        return random_string
    
    def get_id(self) -> int:
        return self._id
    
    def get_interlocutor_id(self) -> str:
        return self._interlocutor_id

    def activate(self) -> None:
        self._frame_input.activate()
        self._button_send_input_message.config(state='normal')

    def inactivate(self) -> None:
        self._frame_input.inactivate()
        self._button_send_input_message.config(state='disabled')
    

class Chats(ttk.Frame):
    def __init__(self, master=None, username=None, command=None, **kwargs) -> None:
        super().__init__(master, **kwargs)

        self._master = master
        self._username = username
        self._command = command
        self._dialogs = {}

        # Создание виджета Notebook
        self._notebook_chats = ttk.Notebook(self)
        self._notebook_chats.pack(expand=True, fill='both', padx=10, pady=10)
    
    def set_username(self, username: str) -> None:
        self._username = username

    def add_dialog(self, dialog_name: str, interlocutor_id: str, dialog_history: list[dict]) -> int:
        # Создание новой вкладки с CustomWidget
        dlg = Dialog(self._notebook_chats, interlocutor_id, username=self._username, dialog_name=dialog_name, command=self._command)
        self._dialogs[dlg.get_id()] = dlg

        dlg.load_history(dialog_history)

        dlg.pack(expand=True, fill='both')

        self._notebook_chats.add(dlg, text=f"{dialog_name}")
        self._notebook_chats.select(self._notebook_chats.index('end') - 1)

        return dlg.get_id()

    def inactivate_dialog(self, dialog_id: int) -> None:
        if dialog_id not in self._dialogs:
            return
        self._dialogs[dialog_id].inactivate()

    def hide_dialog(self, dialog_id: int) -> None:
        if dialog_id not in self._dialogs:
            return
        self._dialogs[dialog_id].pack_forget()
        
    def load_dialog(self, dialog_id: int) -> None:
        if dialog_id not in self._dialogs:
            return
        if not self._dialogs[dialog_id].winfo_viewable():
            self._dialogs[dialog_id].pack(expand=True, fill='both')
        
        self._dialogs[dialog_id].activate()

    def size(self) -> int:
        return len(self._dialogs)
    
    def get_dialog(self, dialog_id: int) -> Dialog:
        if dialog_id not in self._dialogs:
            return None
        return self._dialogs[dialog_id]
    
    def get_current_dialog(self) -> Dialog:
        current_tab = self._notebook_chats.select()
        return self.nametowidget(current_tab)