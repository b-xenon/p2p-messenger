from dataclasses import dataclass

from pydantic import BaseModel

from config import config, IPAddressType, PortType, UserIdHashType, UserIdType
from libs.cryptography import RSA_KeyType


class KnownRSAPublicKeys(BaseModel):
    keys: set[RSA_KeyType] = set()

class DHTNodeInfo(BaseModel):
    ip_address: IPAddressType = ''
    dht_keys: set[str] = set()
 
class DHTNodeHistory(BaseModel):
    nodes_history: list[DHTNodeInfo] = []

    def is_ip_in_history(self, ip_address: IPAddressType) -> bool:
        """
            Проверяет, есть ли указанный IP-адрес в истории узлов.
        
        Args:
            ip_address (IPAddressType): IP адрес, который необходимо проверить.

        Returns:
            bool: True - если есть, иначе False.
        """
        return any(node.ip_address == ip_address for node in self.nodes_history)
    
    def add_new_dht_key(self, ip_address: IPAddressType, dht_key: str) -> bool:
        """
            Добавляет новый DHT ключ в узел с указанным IP-адресом в истории узлов.
        
        Args:
            ip_address (IPAddressType): IP адрес узла в истории узлов.
            dht_key (str): Новый DHT ключ.

        """
        for node in self.nodes_history:
            if node.ip_address == ip_address:
                if dht_key in node.dht_keys:
                    return False
                node.dht_keys.add(dht_key)
                return True
        
        self.nodes_history.append(DHTNodeInfo(ip_address=ip_address, dht_keys=set([dht_key])))
        return True

@dataclass
class ClientInfo:
    user_id: UserIdType = ''
    user_id_hash: UserIdHashType = ''
    user_name: str = ''
    user_password: str = ''
    user_password_hash: str = ''
    user_dht_key: str = ''
    dht_node_ip: IPAddressType = ''
    dht_node_port: PortType = config.NETWORK.DHT.PORT
    dht_client_port: PortType = config.NETWORK.DHT_CLIENT_PORT
    application_port: PortType = config.NETWORK.CLIENT_COMMUNICATION_PORT
    use_local_ip: bool = False
    dht_peers_keys: DHTNodeHistory = DHTNodeHistory()