import os
import logging
from enum import Enum
from datetime import datetime

class MyLoggerType(Enum):
    """ Перечисление для уровней логирования. """
    DEBUG       = logging.DEBUG
    INFO        = logging.INFO
    WARNING     = logging.WARNING
    ERROR       = logging.ERROR
    CRITICAL    = logging.CRITICAL

class MyLogger:
    def __init__(self, logger_name: str, logger_type: MyLoggerType, logger_dir: str, also_use_console: bool = True) -> None:
        """
            Инициализирует объект логгера.

        Args:
            logger_name: Название логгера.
            logger_type: Уровень логирования, используя MyLoggerType.
            logger_dir: Директория, где будет сохраняться лог-файл.
        """
        self.logger = logging.getLogger(logger_name)
        self._logger_format = '[%(levelname)s: [%(name)s] | [%(threadName)s] - %(asctime)s] %(message)s' # [%(thread)d]

        self._setup_logger(logger_type.value, logger_dir, also_use_console)

    def _setup_logger(self, logger_type: int, logger_dir: str, also_use_console: bool) -> None:
        """
            Настройка логгера, включая создание файлового обработчика и консольного обработчика.

        Args:
            logger_type: Уровень логирования как целое число.
            logger_dir: Путь к директории для сохранения лог-файлов.
        """
        self.logger.setLevel(logger_type)
        
        # Формирование имени файла лога с текущей датой и временем
        log_filename = f'{logger_dir}{datetime.now().strftime("%Y_%m_%d-%H_%M_%S")}.log'
        os.makedirs(logger_dir, exist_ok=True)

        # Проверка и удаление существующего файла, если требуется
        if os.path.exists(log_filename):
            os.remove(log_filename)

        file_handler = logging.FileHandler(log_filename, encoding='utf-8')
        file_handler.setFormatter(logging.Formatter(self._logger_format))
        self.logger.addHandler(file_handler)

        # Добавление обработчика вывода в консоль, если это разрешено в конфигурации
        if also_use_console:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(CustomFormatter(self._logger_format))
            self.logger.addHandler(console_handler)


class CustomFormatter(logging.Formatter):
    """ Кастомный форматтер для логгера с цветным выводом в зависимости от уровня логирования. """
    
    COLORS = {
        logging.DEBUG:      "\x1b[32m",     # зеленый
        logging.INFO:       "\x1b[38;20m",  # серый
        logging.WARNING:    "\x1b[33;20m",  # желтый
        logging.ERROR:      "\x1b[31;20m",  # красный
        logging.CRITICAL:   "\x1b[31;1m"    # ярко-красный
    }
    RESET = "\x1b[0m"

    def __init__(self, logger_format: str) -> None:
        super().__init__()

        self._logger_format = logger_format

    def format(self, record: logging.LogRecord) -> str:
        """
            Форматирует запись лога, добавляя цвета в зависимости от уровня логирования.

        Args:
            record: Запись лога.

        Returns:
            Отформатированная строка с цветным выводом.
        """
        log_format = self.COLORS.get(record.levelno, '') + self._logger_format + self.RESET
        _formatter = logging.Formatter(log_format)
        return _formatter.format(record)