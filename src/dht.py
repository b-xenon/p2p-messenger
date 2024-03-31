import asyncio
import sys
from kademlia.network import Server

class KademliaNode:
    def __init__(self, loop):
        self.loop = loop
        self.node = Server()
        self.loop.add_reader(sys.stdin, self.handle_input)

    async def start(self):
        self.node.listen(8468)
        await self.node.bootstrap([])
        print("DHT-node started.")

    async def stop(self):
        await self.node.stop()
        print("DHT-node stopped.")

    def handle_input(self):
        if sys.stdin.readline().strip() == 'q':
            asyncio.ensure_future(self.stop())

async def main():
    loop = asyncio.get_running_loop()
    node = KademliaNode(loop)
    await node.start()

    # Keep the event loop running until the node is stopped
    while True:
        try:
            await asyncio.sleep(1)
        except KeyboardInterrupt:
            print("KeyboardInterrupt, stopping...")
            await node.stop()
            break

if __name__ == "__main__":
    asyncio.run(main())
