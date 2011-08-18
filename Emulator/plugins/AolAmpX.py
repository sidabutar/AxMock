# AOL Radio AOLMediaPlaybackControl.exe
# CVE-2007-6250
class AolAmpX:
    def AolAmpXAppendFileToPlayList(self, arg):
        if len(arg) > 512:
            file = open("AxMockLog.txt", "a")
	    file.write('AOL AmpX overflow in AppendFileToPlayList\n')
            file.close()