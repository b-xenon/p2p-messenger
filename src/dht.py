import asyncio
from kademlia.network import Server
from pydantic import BaseModel

from libs.cryptography import RSA_KeyType
from libs.mylogger import MyLogger, MyLoggerType
from config import config, IPAddressType, PortType

class EmptyDHTDataError(Exception):
    """Исключение возникает, когда не найдено данных для предоставленного ключа."""
    
    def __init__(self, message="Данные для предоставленного ключа не найдены."):
        self.message = message
        super().__init__(self.message)

class DHTPeerProfile(BaseModel):
    """
    Описывает данные узла в распределённой хеш-таблице (DHT).

    Attributes:
        avaliable_ip (IPAddressType): Доступный IP-адрес узла.
        avaliable_port (PortType): Порт, на котором узел принимает соединения.
        rsa_public_key (RSA_KeyType): Публичный ключ RSA пользователя для шифрования или аутентификации.
    """
    avaliable_ip: 'IPAddressType'  # IP-адрес.
    avaliable_port: 'PortType'     # порт.
    rsa_public_key: 'RSA_KeyType'  # Публичный ключ RSA.

class DHT_Client:
    def __init__(self, listen_port: PortType, dht_ip: IPAddressType, dht_port: PortType) -> None:
        """
            Инициализирует клиент DHT.

        Args:
            listen_port: Порт, который будет использоваться для прослушивания входящих соединений.
            dht_ip: IP адрес узла для начального подключения к сети DHT.
            dht_port: Порт узла для начального подключения к сети DHT.
        """
        self._listen_port = listen_port
        self._dht_ip = dht_ip
        self._dht_port = dht_port

        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._server = Server()
        self._loop.run_until_complete(self._init_server())

    async def _init_server(self):
        """
            Асинхронно инициализирует сервер, прослушивает порт и подключается к узлу DHT.
        """
        await self._server.listen(self._listen_port)
        bootstrap_node = (self._dht_ip, self._dht_port)
        await self._server.bootstrap([bootstrap_node])

    def set_data(self, key: str, data: str) -> None:
        """
            Устанавливает данные в DHT.

        Args:
            key: Ключ для данных.
            data: Данные для сохранения.
        """
        self._loop.run_until_complete(self._set_data(key, data))
    
    async def _set_data(self, key: str, data: str) -> None:
        """
            Асинхронно устанавливает данные в DHT.

        Args:
            key: Ключ для данных.
            data: Данные для сохранения.
        """
        await self._server.set(key, data)

    def get_data(self, key: str) -> str:
        """
            Возвращает данные из DHT по заданному ключу.

        Args:
            key: Ключ для извлечения данных.

        Returns:
            Возвращает строку данных, соответствующую ключу.
        
        Raises:
            EmptyDataFromDHT: Если данные по ключу отсутствуют или пусты.
        """
        return self._loop.run_until_complete(self._get_data(key))
    
    async def _get_data(self, key: str) -> str:
        """
            Асинхронно извлекает данные из DHT по заданному ключу.

        Args:
            key: Ключ для извлечения данных.

        Returns:
            Возвращает строку данных, соответствующую ключу.
        
        Raises:
            EmptyDataFromDHT: Если данные по ключу отсутствуют или пусты.
        """
        data = await self._server.get(key)
        if not data:
            raise EmptyDHTDataError
        return data
    
    def stop(self):
        """
            Останавливает сервер и закрывает событийный цикл.
        """
        try:
            self._server.stop()
            self._loop.run_until_complete(asyncio.sleep(1))
            self._loop.close()
        except Exception:
            pass

class KademliaServer:
    def __init__(self, port: PortType) -> None:
        """
            Инициализирует сервер Kademlia.

        Args:
            port: Порт, на котором сервер будет слушать входящие соединения.
        """
        self._port = port
        self._server = Server()
        self._loop = asyncio.get_event_loop()
        self._configure_logging()

    def _configure_logging(self) -> None:
        """
            Настройка логгирования для сервера.
        """
        # Использование настроек логгера из библиотеки 'mylogger'
        self._logger = MyLogger('kademlia', MyLoggerType.DEBUG, config.PATHS.LOG_DHT).logger

    async def _start(self) -> None:
        """
            Асинхронный запуск сервера и прослушивание на заданном порту.
        """
        await self._server.listen(self._port)
        self._logger.debug("Server started")
        self._loop.set_debug(True)

    def _stop(self) -> None:
        """
            Остановка сервера и логгирование этого события.
        """
        self._server.stop()
        self._logger.debug("Server stopped")

    def run_forever(self) -> None:
        """
            Запускает сервер на неопределенный срок, пока не будет получен сигнал прерывания.
        """
        try:
            self._loop.run_until_complete(self._start())
            self._loop.run_forever()
        except KeyboardInterrupt:
            pass
        finally:
            self._stop()
            self._loop.close()
            self._logger.info("Event loop closed.")
            

if __name__ == "__main__":
    server = KademliaServer(config.NETWORK.DHT.PORT)
    server.run_forever()
