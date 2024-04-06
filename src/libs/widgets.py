import tkinter as tk
from tkinter import ttk

import random
import string

import pytz
from datetime import datetime

class Dialog(ttk.Frame):
    objects_counter = 0

    def __init__(self, master, interlocutor_ip, username=None, dialog_name=None, command=None, **kwargs) -> None:
        super().__init__(master, **kwargs)

        self._master = master
        self._interlocutor_ip = interlocutor_ip
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
        self._text_dialog = tk.Text(self, state='disabled')
        self._text_input_message = tk.Text(self, height=4)
        self._button_send_input_message = ttk.Button(self, text="Отправить", command=self.send_message)
        
        self._scrollbar = tk.Scrollbar(self, command=self._text_dialog.yview)
        self._scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Настраиваем виджет Text для работы со Scrollbar
        self._text_dialog.config(yscrollcommand=self._scrollbar.set)

        # Определяем тег для жирного шрифта
        self._text_dialog.tag_configure("bold", font=('Arial', 8, 'bold'))

        # Размещение виджетов в окне
        self._text_dialog.pack(fill='both', expand=True, padx=5, pady=5)
        self._text_input_message.pack(fill='x', padx=5, pady=5)
        self._button_send_input_message.pack(padx=10, pady=10)

    def send_message(self) -> None:
        # Получаем текст из Text widget
        message = self._text_input_message.get("1.0", tk.END).strip()
        
        if message:  # Проверяем, что текст не пустой
            current_time = datetime.now(self._moscow_tz)

            formatted_message = f"[{current_time.strftime('%d.%m.%Y - %H:%M:%S')}] {self._username}: {message}\n"
            self._add_message_to_dialog(formatted_message, len(formatted_message.split(': ')[0]) + 1)

            # Очищаем Text widget
            self._text_input_message.delete("1.0", tk.END)
        
            self._messages.append({
                'author': self._username,
                'msg': message,
                'msg_id': f'm{self._message_id_counter}',
                'time': current_time.isoformat()
            })
            self._message_id_counter += 1

            # Вызов пользовательской функции, если она задана
            if self._command:
                self._command(self._messages[-1])

    def recieve_message(self, message: dict) -> None:
        if message:
            recived_message_time = datetime.fromisoformat(message['time'])
            if len(self._messages):
                last_my_message_time = datetime.fromisoformat(self._messages[-1]['time'])

                if recived_message_time < last_my_message_time:
                    self._restruct_dialog_messages(message)
                    return

            formatted_message = f"[{recived_message_time.strftime('%d.%m.%Y - %H:%M:%S')}] {message['author']}: {message['msg']}\n"
            self._add_message_to_dialog(formatted_message, len(formatted_message.split(': ')[0]) + 1)

            self._messages.append(message)

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


    def _generate_random_name(self) -> str:
        # Строка со всеми буквами и цифрами
        characters = string.ascii_letters + string.digits
        # Выбор случайных символов из строки characters
        random_string = ''.join(random.choice(characters) for i in range(12))
        return random_string
    
    def get_id(self) -> int:
        return self._id
    
    def get_interlocutor_ip(self) -> str:
        return self._interlocutor_ip

    def activate(self) -> None:
        self._text_input_message.config(state='normal')
        self._button_send_input_message.config(state='normal')

    def inactivate(self) -> None:
        self._text_input_message.config(state='disabled')
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
    
    def add_dialog(self, dialog_name: str, interlocutor_ip: str) -> int:
        # Создание новой вкладки с CustomWidget
        dlg = Dialog(self._notebook_chats, interlocutor_ip, username=self._username, dialog_name=dialog_name, command=self._command)
        self._dialogs[dlg.get_id()] = dlg

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