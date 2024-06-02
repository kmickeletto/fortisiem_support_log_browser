import logging
import os
import tempfile
import platform
import logging.handlers
import inspect

class Logger:
    def __init__(self, logger_name, destinations):
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(logging.DEBUG)
        
        for destination in destinations:
            try:
                self.add_handler(destination)
            except Exception as e:
                self.logger.error(f"Failed to add handler: {destination}. Error: {e}", extra={'classname': 'Logger', 'funcname': '__init__'})

    def add_handler(self, destination):
        handler_type = destination.get('type')
        log_level = destination.get('level', logging.DEBUG)

        if handler_type == 'file':
            temp_dir = tempfile.gettempdir()
            log_file = os.path.join(temp_dir, destination.get('destination', 'fortisiem_log_browser.log'))
            handler = logging.FileHandler(log_file, mode='w')
        elif handler_type == 'console':
            handler = logging.StreamHandler()
        elif handler_type == 'syslog':
            if platform.system() == 'Windows':
                raise NotImplementedError("Syslog is not supported on Windows")
            address = destination.get('destination', 'localhost:514').split(':')
            handler = logging.handlers.SysLogHandler(address=(address[0], int(address[1])))
        else:
            raise ValueError(f"Unsupported handler type: {handler_type}")

        handler.setLevel(log_level)
        formatter = logging.Formatter('%(asctime)s [%(funcname)s]:[class]=%(classname)s,[eventSeverity]=%(levelname)s,[lineNumber]=%(custom_lineno)d,[phLogDetail]=%(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def get_logger(self, obj):
        class CustomLoggerAdapter(logging.LoggerAdapter):
            def process(self, msg, kwargs):
                frame = inspect.currentframe().f_back.f_back.f_back
                func_name = frame.f_code.co_name
                line_no = frame.f_lineno
                kwargs['extra'] = kwargs.get('extra', {})
                kwargs['extra']['classname'] = obj.__class__.__name__
                kwargs['extra']['funcname'] = func_name
                kwargs['extra']['custom_lineno'] = line_no
                return msg, kwargs

        return CustomLoggerAdapter(self.logger, {})

    def log_method(self, func):
        def wrapper(*args, **kwargs):
            class_name = args[0].__class__.__name__
            func_name = func.__name__.upper()
            logger = logging.LoggerAdapter(self.logger, {'classname': class_name, 'funcname': func_name})
            logger.debug(f"Entering {class_name}.{func_name}")
            try:
                result = func(*args, **kwargs)
            except Exception as e:
                logger.error(f"Exception in {class_name}.{func_name}: {e}", exc_info=True)
                raise
            logger.debug(f"Exiting {class_name}.{func_name}")
            return result
        return wrapper

class DummyLogger:
    def __getattr__(self, name):
        return lambda *args, **kwargs: None

def get_logger_instance():
    if 'Logger' in globals():
        return Logger
    else:
        return DummyLogger