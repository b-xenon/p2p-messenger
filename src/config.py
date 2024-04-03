# ----Logger----
LOGGER_DEBUG_MODE = False
LOGGER_WITHOUT_CONSOLE = False
# --------------

# ---Network---
PORT_DHT = 60800
PORT_CLIENT_CONNECTION_CHECKING = 60801
PORT_CLIENT_COMMUNICATION = 60802

PING_INTERVAL = 5
PING_TIMEOUT = 10

MESSAGE_INIT = 0
MESSAGE_ACK = 1

MESSAGE_PING = 2
MESSAGE_PONG = 3
# -------------




# ----Pathes----
paths = {'stuff': 'stuff'}
paths = {
    'dirs': {
        'log_dht': f'{paths["stuff"]}/log/dht/',
        'log_client': f'{paths["stuff"]}/log/client/',
    }
}
# --------------