# Chinagames iGame CGAgent ActiveX Control Buffer Overflow
# CVE-2009-1800
class CGAgent:
    def CGAgentCreateChinagames(self, arg0):
        if len(arg0)>428:
            file = open("AxMockLog.txt", "a")
	    file.write('CGAgent ActiveX CreateChinagames Method BUffer Overflow\n')
            file.close()