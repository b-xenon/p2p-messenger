import asyncio
from kademlia.network import Server
from libs.mylogger import MyLogger, MyLoggerType

from config import config

class KademliaServer:
    def __init__(self, port: int = config.NETWORK.DHT.PORT) -> None:
        """
            Инициализирует сервер Kademlia.

        Args:
            port: Порт, на котором сервер будет слушать входящие соединения.
        """
        self.port = port
        self.server = Server()
        self.loop = asyncio.get_event_loop()
        self._configure_logging()

    def _configure_logging(self) -> None:
        """
            Настройка логгирования для сервера.
        """
        # Использование настроек логгера из библиотеки 'mylogger'
        self.logger = MyLogger('kademlia', MyLoggerType.DEBUG, config.PATHS.LOG_DHT).logger

    async def _start(self) -> None:
        """
            Асинхронный запуск сервера и прослушивание на заданном порту.
        """
        await self.server.listen(self.port)
        self.logger.debug("Server started")
        self.loop.set_debug(True)

    def _stop(self) -> None:
        """
            Остановка сервера и логгирование этого события.
        """
        self.server.stop()
        self.logger.debug("Server stopped")

    def run_forever(self) -> None:
        """
            Запускает сервер на неопределенный срок, пока не будет получен сигнал прерывания.
        """
        try:
            self.loop.run_until_complete(self._start())
            self.loop.run_forever()
        except KeyboardInterrupt:
            pass
        finally:
            self._stop()
            self.loop.close()
            self.logger.info("Event loop closed.")
            

if __name__ == "__main__":
    server = KademliaServer()
    server.run_forever()
