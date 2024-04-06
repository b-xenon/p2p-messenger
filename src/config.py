# ----Logger----
LOGGER_DEBUG_MODE = False
LOGGER_WITHOUT_CONSOLE = False
# --------------

# ---Network---
PORT_DHT = 60800
PORT_CLIENT_COMMUNICATION = 60801

PING_INTERVAL = 5
PING_TIMEOUT = 10
# -------------

# ---Widgets---
MAX_TEXT_SYMBOLS_NUMBER = 5000
# -------------

# ----Pathes----
paths = {'stuff': 'stuff'}
paths = {
    'dirs': {
        'log_dht': f'{paths["stuff"]}/log/dht/',
        'log_client': f'{paths["stuff"]}/log/client/',
    },
    'files': {
        'db': f'{paths["stuff"]}/history_chats.db'
    }
}
# --------------