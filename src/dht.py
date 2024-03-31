import asyncio
from kademlia.network import Server
from libs.myformatter import MyLogger, MyLoggerType

import config

class KademliaServer:
    def __init__(self, port=8468):
        self.port = port
        self.server = Server()
        self.loop = asyncio.get_event_loop()
        self._configure_logging()

    def _configure_logging(self):
        self.logger = MyLogger('kademlia', MyLoggerType.DEBUG, config.paths["dirs"]["log_dht"]).logger

    async def _start(self):
        await self.server.listen(self.port)
        self.logger.debug("Server started")
        self.loop.set_debug(True)

    def _stop(self):
        self.server.stop()
        self.logger.debug("Server stopped")

    def run_forever(self):
        try:
            self.loop.run_until_complete(self._start())
            self.loop.run_forever()
        except KeyboardInterrupt:
            pass
        finally:
            self._stop()
            self.loop.close()

if __name__ == "__main__":
    server = KademliaServer()
    server.run_forever()
