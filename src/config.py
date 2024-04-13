from platform import system
from typing import Literal, NamedTuple

class _LoggerConfig(NamedTuple):
    DEBUG_MODE: bool
    WITHOUT_CONSOLE: bool

class _NetworkDHTConfig(NamedTuple):
    PORT: int
    IP: str

class _NetworkPingConfig(NamedTuple):
    INTERVAL: int
    TIMEOUT: int

class _NetworkConfig(NamedTuple):
    DHT: _NetworkDHTConfig
    CLIENT_COMMUNICATION_PORT: int
    PING: _NetworkPingConfig

class _FontConfig(NamedTuple):
    FAMILY: str
    SIZE: int
    WEIGHT: Literal["normal", "bold"]
    SLANT: Literal["roman", "italic"]

class _WidgetsConfig(NamedTuple):
    MAX_TEXT_SYMBOLS_NUMBER: int
    MAX_FILE_SIZE: int
    DIALOG_TEXT_FONT: _FontConfig
    DIALOG_AUTHOR_FONT: _FontConfig
    INPUT_TEXT_FONT: _FontConfig

class _PathConfig(NamedTuple):
    LOG_DHT: str
    LOG_CLIENT: str
    DOWNLOAD: str
    THEMES: str
    ICONS: str
    KEYS: str

class _IconConfig(NamedTuple):
    MAIN: str
    INFO_L: str
    INFO_S: str
    WARNING_L: str
    WARNING_S: str
    ERROR_L: str
    ERROR_S: str
    SUCCESS_L: str
    SUCCESS_S: str

class _ThemeConfig(NamedTuple):
    DARK: str
    LIGHT: str
    DEFAULT: str

class _FilesConfig(NamedTuple):
    HISTORY: str
    CONFIG: str
    DB_KEY: str
    RSA_PRIV: str
    RSA_PUB: str
    THEMES: _ThemeConfig
    ICONS: _IconConfig

class _Config(NamedTuple):
    LOGGER: _LoggerConfig = _LoggerConfig(DEBUG_MODE=True, WITHOUT_CONSOLE=False)
    
    NETWORK: _NetworkConfig = _NetworkConfig(
        DHT=_NetworkDHTConfig(
            PORT = 60800,
            IP   = '192.168.31.169'
        ),
        CLIENT_COMMUNICATION_PORT=60801,
        PING=_NetworkPingConfig(INTERVAL=5, TIMEOUT=10)
    )

    WIDGETS: _WidgetsConfig = _WidgetsConfig(
        MAX_TEXT_SYMBOLS_NUMBER = 5000,
        MAX_FILE_SIZE           = 5000,
        DIALOG_AUTHOR_FONT      = _FontConfig(
            FAMILY  = 'Calibri',
            SIZE    = 10,
            WEIGHT  = 'bold',
            SLANT   = 'roman'
        ),
        DIALOG_TEXT_FONT        = _FontConfig(
            FAMILY  = 'Calibri',
            SIZE    = 10,
            WEIGHT  = 'normal',
            SLANT   = 'roman'
        ),
        INPUT_TEXT_FONT         = _FontConfig(
            FAMILY  = 'Calibri',
            SIZE    = 10,
            WEIGHT  = 'normal',
            SLANT   = 'roman'
        )
    )

    THEME: _ThemeConfig = _ThemeConfig(
        DARK    = 'forest-dark',
        LIGHT   = 'forest-light',
        DEFAULT = 'vista' if system() == 'Windows' else 'clam'
    )

    BASE_PATH: str = 'stuff'
    PATHS: _PathConfig = _PathConfig(
        LOG_DHT     = f'{BASE_PATH}/log/dht/',
        LOG_CLIENT  = f'{BASE_PATH}/log/client/',
        DOWNLOAD    = 'download',
        THEMES       = f'{BASE_PATH}/themes/',
        ICONS       = f'{BASE_PATH}/icons/',
        KEYS        = f'{BASE_PATH}/keys/'
    )
    FILES: _FilesConfig = _FilesConfig(
        HISTORY     = f'{BASE_PATH}/history.db',
        CONFIG      = f'{BASE_PATH}/config.ini',
        DB_KEY      = 'database_key.key',
        RSA_PRIV    = 'rsa_key',
        RSA_PUB     = 'rsa_key.pub',
        THEMES      = _ThemeConfig(
            DARK    = f'{PATHS.THEMES}forest-dark.tcl',
            LIGHT   = f'{PATHS.THEMES}forest-light.tcl',
            DEFAULT = ''
            ),
        ICONS       = _IconConfig(
            MAIN        = f'{PATHS.ICONS}icon.ico',
            INFO_L      = f'{PATHS.ICONS}info_64.ico',
            INFO_S      = f'{PATHS.ICONS}info_32.ico',
            WARNING_L   = f'{PATHS.ICONS}warn_64.ico',
            WARNING_S   = f'{PATHS.ICONS}warn_32.ico',
            ERROR_L     = f'{PATHS.ICONS}err_64.ico',
            ERROR_S     = f'{PATHS.ICONS}err_32.ico',
            SUCCESS_L   = f'{PATHS.ICONS}suc_64.ico',
            SUCCESS_S   = f'{PATHS.ICONS}suc_32.ico',
        )
    )

config = _Config()
