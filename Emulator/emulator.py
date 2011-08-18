import sys

class Emulator:
    _public_methods_ = []
    


from config import *

Emulator.__bases__ += plugin_class
Emulator._public_methods_ += plugin_method
Emulator._reg_clsid_ = "{09F9C742-E5AA-45FD-A8E0-6220954D2BBB}"
Emulator._reg_progid_ = "AxMock"
