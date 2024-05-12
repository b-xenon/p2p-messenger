from platform import system
from typing import Literal, NamedTuple, Union

UserIdType = str
UserIdHashType = str
IPAddressType = str
PortType = int

FilenameType = str
PathType = str

class _LoggerConfig(NamedTuple):
    DEBUG_MODE: bool
    WITHOUT_CONSOLE: bool

class _NetworkDHTConfig(NamedTuple):
    PORT: PortType
    IP: IPAddressType

class _NetworkPingConfig(NamedTuple):
    INTERVAL: int
    TIMEOUT: int

class _NetworkConfig(NamedTuple):
    DHT: _NetworkDHTConfig
    DHT_CLIENT_PORT: PortType
    CLIENT_COMMUNICATION_PORT: PortType
    PING: _NetworkPingConfig

class _FontConfig(NamedTuple):
    FAMILY: str
    SIZE: int
    WEIGHT: Literal["normal", "bold"]
    SLANT: Literal["roman", "italic"]

class _TooltipConfig(NamedTuple):
    TEXT_FONT: _FontConfig
    DELAY: int

class _WidgetDescription(NamedTuple):
    USER_ID: str
    USER_PASSWORD: str
    USER_NAME: str
    USER_DHT_KEY: str
    DHT_NODE_IP: str
    DHT_NODE_PORT: str
    DHT_CLIENT_PORT: str
    APP_PORT: str
    ALIEN_DHT_KEY: str

class _WidgetsConfig(NamedTuple):
    MAX_TEXT_SYMBOLS_NUMBER: int
    MAX_FILE_SIZE: int
    DIALOG_TEXT_FONT: _FontConfig
    DIALOG_AUTHOR_FONT: _FontConfig
    INPUT_TEXT_FONT: _FontConfig
    TOOLTIP_SETTINGS: _TooltipConfig
    DESCRIPTIONS: _WidgetDescription

class _PathConfig(NamedTuple):
    LOG_DHT: PathType
    LOG_CLIENT: PathType
    DOWNLOAD: PathType
    THEMES: PathType
    ICONS: PathType
    KEYS: PathType

class _IconConfig(NamedTuple):
    MAIN: FilenameType
    INFO_L: FilenameType
    INFO_S: FilenameType
    WARNING_L: FilenameType
    WARNING_S: FilenameType
    ERROR_L: FilenameType
    ERROR_S: FilenameType
    SUCCESS_L: FilenameType
    SUCCESS_S: FilenameType

class _ThemeConfig(NamedTuple):
    NIGHT: Union[str, PathType]
    LIGHT: Union[str, PathType]
    DEFAULT: Union[str, PathType]

class _FilesConfig(NamedTuple):
    HISTORY: FilenameType
    CONFIG: FilenameType
    ACCOUNTS: FilenameType
    RSA_PRIV: FilenameType
    RSA_PUB: FilenameType
    THEMES: _ThemeConfig
    ICONS: _IconConfig

class _Config(NamedTuple):
    LOGGER: _LoggerConfig = _LoggerConfig(DEBUG_MODE=True, WITHOUT_CONSOLE=False)
    
    USER_ID_HASH_POSTFIX_SIZE: int = 10

    NETWORK: _NetworkConfig = _NetworkConfig(
        DHT=_NetworkDHTConfig(
            PORT = 60800,
            IP   = '192.168.31.169'
        ),
        DHT_CLIENT_PORT=60798, 
        CLIENT_COMMUNICATION_PORT=60801,
        PING=_NetworkPingConfig(INTERVAL=5, TIMEOUT=15)
    )

    WIDGETS: _WidgetsConfig = _WidgetsConfig(
        MAX_TEXT_SYMBOLS_NUMBER = 5000,
        MAX_FILE_SIZE           = 100_000_000,
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
        ),
        TOOLTIP_SETTINGS        = _TooltipConfig(
            TEXT_FONT = _FontConfig(
                FAMILY  = 'Calibri',
                SIZE    = 10,
                WEIGHT  = 'normal',
                SLANT   = 'roman'
            ),
            DELAY      = 1000
        ),
        DESCRIPTIONS            = _WidgetDescription(
            USER_ID = "ID представляет из себя ваш логин.\n"
                "К нему привязаны все ваши диалоги.\n"
                "Может быть любым, но должен быть уникальным, чтобы избежать коллизии.",
            USER_PASSWORD = "Пароль от аккаунта для введенного ID.",
            USER_NAME = "Данное имя будет отображаться в чатах у вас и ваших собеседников в виде вашего Никнейма.",
            USER_DHT_KEY = "По данному DHT ключу в распределенной хэш таблице будут записаны ваши данные.\n"
                "Для начала общения с вами, вашему собеседнику нужно будет узнать данный DHT ключ.\n"
                "Может быть любым, но должен быть уникальным, чтобы избежать коллизии.",
            DHT_NODE_IP = "IPv4 адрес начальной DHT-node, в сети которой вы хотите хранить ваш DHT ключ.",
            DHT_NODE_PORT = "Порт начальной DHT-node, который она прослушивает\n"
                "и в сети которой вы хотите хранить ваш DHT ключ.",
            DHT_CLIENT_PORT = "Порт, который будет прослушивать DHT-node клиента\n"
                "и к которому смогут подключаться другие DHT-node в сети DHT.",
            APP_PORT = "Порт, который будет прослушивать приложение\n"
                "и по которому к вам будут подключаться другие пользователи.",
            ALIEN_DHT_KEY = "По данному DHT ключу в распределенной хэш таблице записаны данные вашего собеседника."
        )
    )

    THEME: _ThemeConfig = _ThemeConfig(
        NIGHT   = 'forest-dark',
        LIGHT   = 'forest-light',
        DEFAULT = 'vista' if system() == 'Windows' else 'clam'
    )

    BASE_PATH: str = 'stuff'
    PATHS: _PathConfig = _PathConfig(
        LOG_DHT     = f'{BASE_PATH}/log/dht/',
        LOG_CLIENT  = f'{BASE_PATH}/log/client/',
        DOWNLOAD    = 'download',
        THEMES      = f'{BASE_PATH}/themes/',
        ICONS       = f'{BASE_PATH}/icons/',
        KEYS        = f'{BASE_PATH}/keys/'
    )
    FILES: _FilesConfig = _FilesConfig(
        HISTORY     = f'{BASE_PATH}/history.db',
        CONFIG      = f'{BASE_PATH}/config.ini',
        ACCOUNTS    = f'{BASE_PATH}/accounts.db',
        RSA_PRIV    = 'rsa_key',
        RSA_PUB     = 'rsa_key.pub',
        THEMES      = _ThemeConfig(
            NIGHT   = f'{PATHS.THEMES}forest-dark.tcl',
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
