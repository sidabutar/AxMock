import time
class Recorder:
    _public_methods_ = ['Judge', 'Parameter2', 'Parameter1']
    _reg_progid_ = "Axmock.Recorder"
    _reg_clsid_ = "{2EDAC2EF-B4B9-4772-AF42-23193967E250}" # Results from "print pythoncom.CreateGuid()"
    
    def Parameter2(self, arg1, arg2):
        file = open("AxMockLog.txt", "a")
	file.write(time.strftime('[%Y-%m-%d %H:%M:%S] ', time.localtime(time.time())))
	file.write('Recorder is calling 2Parameter funtion with: \n')
        file.write('arg1: ' + repr(arg1) + '\n')
	file.write('arg2: ' + repr(arg2) + '\n')
        file.close()

    def Parameter1(self, arg1):
	file = open("AxMockLog.txt", "a")
	file.write(time.strftime('[%Y-%m-%d %H:%M:%S] ', time.localtime(time.time())))
	file.write('Recorder is calling 1Parameter funtion with: \n')
	file.write('arg1: ' + repr(arg1) + '\n')
        file.close()
	
    def Judge(self, arg1 = 0, arg2 = 0):
	file = open("AxMockLog.txt", "a")
	file.write(time.strftime('[%Y-%m-%d %H:%M:%S] ', time.localtime(time.time())))
	file.write("Recorder is Judging...\n")
	file.close()

if __name__=='__main__':
    print "Registering recorder..."
    import win32com.server.register
    win32com.server.register.UseCommandLine(Recorder)