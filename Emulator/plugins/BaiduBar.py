# BaiduBar.dll ActiveX DloadDS() Remote Code Execution Vulnerability
# BUGTRAQ  ID: 25121
class BaiduBar:
    def BaiduBarToolDloadDS(self, arg0,arg1,arg2):
	if(str(arg0).lower().find(".cab")!= -1):
            file = open("AxMockLog.txt", "a")
	    file.write('BaiduBar.dll ActiveX DloadDS() function is to download ' + arg0 + '\n')
            file.close()
