# KingView ActiveX Control 'ValidateUser'
# Method Arbitrary File Download Vulnerability
import time
class KingView:
    def KingViewValidateUser(self, arg1, arg2):
        file = open("AxMockLog.txt", "a")
	file.write(time.strftime('[%Y-%m-%d %H:%M:%S] ', time.localtime(time.time())))
	file.write('KingView ActiveX Control is calling ValidateUser funtion with: \n')
        file.write('arg1: ' + arg1 + '\n')
	file.write('arg2: ' + repr(arg2) + '\n')
        file.close()