# ----Logger----
LOGGER_DEBUG_MODE = True
LOGGER_WITHOUT_CONSOLE = False
# --------------

# ---Network---
PORT_DHT = 60800
IP_DHT = '192.168.31.169'
PORT_CLIENT_COMMUNICATION = 60801

PING_INTERVAL = 5
PING_TIMEOUT = 10
# -------------

# ---Widgets---
MAX_TEXT_SYMBOLS_NUMBER = 5000
# -------------

from platform import system
DEFAULT_THEME = 'vista' if system() == 'Windows' else 'clam'

# ----Pathes----
paths = {'stuff': 'stuff'}
paths = {
    'dirs': {
        'stuff': f'{paths["stuff"]}',
        'log_dht': f'{paths["stuff"]}/log/dht/',
        'log_client': f'{paths["stuff"]}/log/client/',
        'download': 'download',
        'theme': f'{paths["stuff"]}/themes/',
        'icons': f'{paths["stuff"]}/icons/'
    }
}
paths.update({
    'files': {
        'history': f'{paths["dirs"]["stuff"]}/history.db',
        'icon': {
            'main': f'{paths["dirs"]["icons"]}/icon.ico',
            'info_l': f'{paths["dirs"]["icons"]}/info_64.ico',
            'info_s': f'{paths["dirs"]["icons"]}/info_32.ico',
            'warning_l': f'{paths["dirs"]["icons"]}/warn_64.ico',
            'warning_s': f'{paths["dirs"]["icons"]}/warn_32.ico',
            'error_l': f'{paths["dirs"]["icons"]}/err_64.ico',
            'error_s': f'{paths["dirs"]["icons"]}/err_32.ico',
            'success_l': f'{paths["dirs"]["icons"]}/suc_64.ico',
            'success_s': f'{paths["dirs"]["icons"]}/suc_32.ico',
            },
        'config': f'{paths["dirs"]["stuff"]}/config.ini',
        'key': f'{paths["dirs"]["stuff"]}/key.key',
        'theme': {
            'dark': 'forest-dark',
            'light': 'forest-light'
        }
    }
})
# --------------