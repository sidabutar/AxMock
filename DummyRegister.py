import win32com.server.register
class Dummy:
	_public_methods_ = []
	_reg_progid_ = "AolAmpX"
	_reg_clsid_ = "{B49C4597-8721-4789-9250-315DFBD9F525}"
if __name__=='__main__':
	print "Registering COM server..."
	for line in open("emulating.txt", "r"):
		word = line.split()
		Dummy._reg_progid_ = word[2]
		Dummy._reg_clsid_ = word[1]
		print "Progid: " + Dummy._reg_progid_
		print "Classid: " + Dummy._reg_clsid_
		win32com.server.register.UseCommandLine(Dummy)
	for line in open("existing.txt", "r"):	
		word = line.split()
		Dummy._reg_progid_ = word[1]
		Dummy._reg_clsid_ = word[0]
		print "Progid: " + Dummy._reg_progid_
		print "Classid: " + Dummy._reg_clsid_
		win32com.server.register.UseCommandLine(Dummy)


