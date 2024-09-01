"""BasePlugin plugin for CyvoreOS"""

import logging
from abc import ABC, abstractmethod
from cyvoreos.check_types import Check

class BasePlugin(ABC):
    """
    Base plugin, abstract class
    """

    name = "Base"
    description = "Base plugin, abstract class"
    tags = []

    @staticmethod
    @abstractmethod
    def run(check: Check, logger: logging.Logger = logging):
        """
        Run the plugin
        
        Parameters:
            check (Check): Check object containing the data to be processed
            logger (Logger): Logger (optional)
        """

        raise NotImplementedError("run method must be implemented")
    
    @staticmethod
    @abstractmethod
    def print(output: str, logger: logging.Logger = logging):
        """
        Prettiy print the output of the plugin

        Parameters:
            output (str): Output of the plugin
            logger (Logger): Logger (optional)
        """

        raise NotImplementedError("print method must be implemented")
    