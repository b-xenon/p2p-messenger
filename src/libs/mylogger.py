import os
import logging
import config
from datetime import datetime

class MyLoggerType:
    DEBUG       = logging.DEBUG
    INFO        = logging.INFO
    WARNING     = logging.WARNING
    ERROR       = logging.ERROR
    CRITICAL    = logging.CRITICAL

class MyLogger:
    def __init__(self, logger_name: str, logger_type: int, logger_dir: str) -> None:
        self.logger = logging.getLogger(logger_name)
        self._logger_format = '[%(levelname)s: [%(name)s] | [%(thread)d] - %(asctime)s] %(message)s'

        self._setup_logger(logger_type, logger_dir)

    def _setup_logger(self, logger_type: int, logger_dir: str) -> None:
        self.logger.setLevel(logger_type)

        # Получаем текущую дату и время
        current_datetime = datetime.now()
        
        # Форматируем строку в нужном формате: yyyy_mm_dd-HH_MM.txt
        log_filename = f'{logger_dir}{current_datetime.strftime("%Y_%m_%d-%H_%M_%S")}.log'
        os.makedirs(logger_dir, exist_ok=True)
        if os.path.exists(log_filename):
            os.remove(log_filename)

        file_handler = logging.FileHandler(log_filename, encoding='utf-8')
        file_handler.setFormatter(logging.Formatter(self._logger_format))
        self.logger.addHandler(file_handler)

        if not config.LOGGER_WITHOUT_CONSOLE:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(CustomFormatter(self._logger_format))
            self.logger.addHandler(console_handler)


class CustomFormatter(logging.Formatter):
    _red = "\x1b[31;20m"
    _grey = "\x1b[38;20m"
    _green = "\x1b[32m"
    _yellow = "\x1b[33;20m"
    _bold_red = "\x1b[31;1m"
    _reset = "\x1b[0m"

    def __init__(self, logger_format: str) -> None:
        super().__init__()

        self._FORMATS = {
            logging.DEBUG:      self._green     + logger_format + self._reset,
            logging.INFO:       self._grey      + logger_format + self._reset,
            logging.WARNING:    self._yellow    + logger_format + self._reset,
            logging.ERROR:      self._red       + logger_format + self._reset,
            logging.CRITICAL:   self._bold_red  + logger_format + self._reset
        }

    def format(self, record: logging.LogRecord) -> str:
        _logger_format = self._FORMATS.get(record.levelno)
        _formatter = logging.Formatter(_logger_format)
        return _formatter.format(record)