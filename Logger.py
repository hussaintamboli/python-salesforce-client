import logging, logging.handlers
import os
import ConfigParser
from datetime import datetime

class Singleton(type):
    """This class is a metaclass of Logger class. It make it singleton.
    """
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
	
        return cls._instances[cls]


class Logger(object):
    """Uses python's loggin library and provides user with a facilty to put logs into a log file. This helps in debugging the code. It is a rotating logger.
    """
    __metaclass__ = Singleton

    def __init__(self, config =None, fileName = __file__):
    	    self.logger = logging.getLogger(os.path.relpath(fileName))
            self.logger.setLevel(logging.DEBUG)
            self.logSection = 'log'
            self.logFile = config.get(self.logSection, 'logFile') 
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

	    # For rotating logger, added below lines
	    # Type of time interval
            # S: Seconds, M: Minutes, H: Hours, D: Days, W: Week day, midnight: Roll over at midnight
            rotationHandler = logging.handlers.TimedRotatingFileHandler(self.logFile, when='D')
	    rotationHandler.setFormatter(formatter)
            self.logger.addHandler(rotationHandler)

    def info(self, msg):
    	"""LogLevel: INFO.
	"""
        self.logger.info(msg)
        
    def warn(self, msg):
    	"""LogLevel: WARNING.
	"""
        self.logger.warn(msg)
        
    def error(self, msg):
    	"""LogLevel: ERROR.
	"""
        self.logger.error(msg)
        
    def critical(self, msg):
    	"""LogLevel: CRITICAL.
	"""
        self.logger.critical(msg)
    
    def debug(self, msg):
    	"""LogLevel: DEBUG.
	"""
        self.logger.debug(msg)
        
if __name__ == '__main__':
    config = ConfigParser.ConfigParser()
    config.read('./conf/sfconfig.cnf')
    log = Logger(config)
    log.info('started using logging')
