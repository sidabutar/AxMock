from emulator import *

if __name__=='__main__':
    print "Registering Emulator..."
    print Emulator._reg_clsid_
    print Emulator._public_methods_
    print Emulator.__bases__
    import win32com.server.register
    win32com.server.register.UseCommandLine(Emulator)