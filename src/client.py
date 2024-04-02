import tkinter
from tkinter import ttk

import socket
import requests

import re
import config
from libs.myformatter import MyLogger, MyLoggerType
from libs import widgets

class WinApp(tkinter.Tk):
    def __init__(self, use_local_ip: bool = True) -> None:
        super().__init__()
        self._use_local_ip = use_local_ip
        self._logger = MyLogger('client', MyLoggerType.DEBUG, config.paths["dirs"]["log_client"]).logger
        self._ip_address = self._get_ip_address()

        self._active_clients = []

        self.title(f"Client {self._ip_address}")
        self.geometry('750x700')
        self.minsize(750, 700)

        self._frame_main = ttk.Frame(self)
        self._frame_main.pack(expand=True, fill='both')

        self._frame_connect_to_another_client = ttk.Frame(self._frame_main)
        self._frame_connect_to_another_client.pack(expand=True, fill='both')

        self._entry_another_client_ip_var = tkinter.StringVar()
        self._entry_another_client_ip = ttk.Entry(self._frame_connect_to_another_client, width=30,
                                                   textvariable=self._entry_another_client_ip_var)
        self._entry_another_client_ip.pack(padx=10, pady=10)

        self._button_connect_to_another_client = ttk.Button(self._frame_connect_to_another_client, text='Подключиться',
                                                             width=30, command=self._connect_to_another_client)
        self._button_connect_to_another_client.pack(padx=10, pady=10)
        
        self._chats = widgets.Chats(self._frame_main, self._ip_address, lambda: self._send_message_to_another_client())

    def _get_ip_address(self) -> str:
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

    def _connect_to_another_client(self):
        another_client_ip = self._entry_another_client_ip_var.get() 
        
        if not another_client_ip:
            self._logger.error("Перед подключением необходимо ввести ip-адрес устройства!")
            return
        
        if not self._is_ipv4(another_client_ip):
            self._logger.error(f"Введен некорректный ip-адрес [{another_client_ip}]!"
                               f" Ip-адрес должен быть в формате IPv4!")
            return
        
        if another_client_ip in self._active_clients:
            self._logger.debug(f"Диалог с клиентом {another_client_ip} уже открыт.")
            return
        
        if not self._chats.size():
            self._chats.pack(expand=True, fill='both', padx=10, pady=10)

        self._chats.add_chat(another_client_ip)
        self._active_clients.append(another_client_ip)

    def _is_ipv4(self, addr: str) -> bool:
        # Регулярное выражение для проверки IPv4
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(pattern, addr):
            # Проверяем, что каждый октет находится в диапазоне от 0 до 255
            parts = addr.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        return False
    
    def _send_message_to_another_client(self):
        pass


    def run(self) -> None:
        self.mainloop()

    class Session:
        def __init__(self) -> None:
            pass


if __name__ == "__main__":
    winapp = WinApp()
    winapp.run()

# import asyncio
# import sys

# from kademlia.network import Server

# async def run():
#     server = Server()
#     await server.listen(8469)

#     bootstrap_node = ('192.168.31.169', 8468)
#     await server.bootstrap([bootstrap_node])

#     await server.set("aboba", "Hello world!")

#     server.stop()

# asyncio.run(run())