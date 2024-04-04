import tkinter as tk
from tkinter import ttk

import random
import string

class Dialog(ttk.Frame):
    objects_counter = 0

    def __init__(self, master, username=None, dialog_name=None, command=None, **kwargs) -> None:
        super().__init__(master, **kwargs)

        self._master = master
        self._username = username if username is not None else self._generate_random_name()
        self._command = command
        
        self._dialog_name = dialog_name if dialog_name is not None else self._generate_random_name()
        self._id = Dialog.objects_counter
        Dialog.objects_counter += 1

        # Создание виджетов Text и Button
        self._text_dialog = tk.Text(self, state='disabled')
        self._text_input_message = tk.Text(self, height=4)
        self._button_send_input_message = ttk.Button(self, text="Отправить", command=self.send_message)
        
        # Размещение виджетов в окне
        self._text_dialog.pack(fill='both', expand=True, padx=5, pady=5)
        self._text_input_message.pack(fill='x', padx=5, pady=5)
        self._button_send_input_message.pack(padx=10, pady=10)

    def send_message(self) -> None:
        # Получаем текст из Text widget
        message = self._text_input_message.get("1.0", tk.END).strip()
        
        if message:  # Проверяем, что текст не пустой
            formatted_message = f"{self._username}: {message}\n"

            # # Разбиваем сообщение на строки
            # lines = message.split('\n')
            # # Форматируем первую строку с IP-адресом
            # formatted_message = f"{self._username}: {lines[0]}\n"
            # # Подготавливаем префикс для последующих строк
            # prefix = " " * (len(self._username) + 2)  # 2 дополнительных символа для ': ' после IP
            # # Форматируем оставшиеся строки, если они есть
            # if len(lines) > 1:
            #     for line in lines[1:]:
            #         formatted_message += f"{prefix}{line}\n"

            # Добавляем сообщение в конец
            self._text_dialog.config(state='normal')
            self._text_dialog.insert(tk.END, f'{formatted_message}')
            self._text_dialog.config(state='disabled')
            # Очищаем Text widget
            self._text_input_message.delete("1.0", tk.END)
        
            # Вызов пользовательской функции, если она задана
            if self._command:
                self._command()

    def recieve_message(self, interlocutor_name: str, message: str) -> None:
        if message:
            formatted_message = f"{interlocutor_name}: {message}\n"

            # Добавляем сообщение в конец
            self._text_dialog.config(state='normal')
            self._text_dialog.insert(tk.END, f'{formatted_message}')
            self._text_dialog.config(state='disabled')

    def _generate_random_name(self) -> str:
        # Строка со всеми буквами и цифрами
        characters = string.ascii_letters + string.digits
        # Выбор случайных символов из строки characters
        random_string = ''.join(random.choice(characters) for i in range(12))
        return random_string
    
    def get_id(self):
        return self._id
    
class Chats(ttk.Frame):
    def __init__(self, master=None, username=None, command=None, **kwargs) -> None:
        super().__init__(master, **kwargs)

        self._master = master
        self._username = username
        self._command = command
        self._dialogs = []

        # Создание виджета Notebook
        self._notebook_chats = ttk.Notebook(self)
        self._notebook_chats.pack(expand=True, fill='both', padx=10, pady=10)
    
    def add_dialog(self, dialog_name: str) -> int:
        # Создание новой вкладки с CustomWidget
        self._dialogs.append(Dialog(self._notebook_chats, username=self._username, dialog_name=dialog_name, command=self._command))

        self._dialogs[-1].pack(expand=True, fill='both')

        self._notebook_chats.add(self._dialogs[-1], text=f"{dialog_name}")
        self._notebook_chats.select(self._notebook_chats.index('end') - 1)

        return self._dialogs[-1].get_id()

    def hide_dialog(self, dialog_id: int) -> None:
        if dialog_id >= len(self._dialogs) or dialog_id < 0:
            return
        self._dialogs[dialog_id].pack_forget()
        
    def load_dialog(self, dialog_id: int) -> None:
        if dialog_id >= len(self._dialogs) or dialog_id < 0:
            return
        self._dialogs[dialog_id].pack(expand=True, fill='both')

    def size(self) -> int:
        return len(self._dialogs)