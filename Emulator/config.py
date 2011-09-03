from plugins.AolAmpX import AolAmpX
from plugins.CGAgent import CGAgent
from plugins.BaiduBar import BaiduBar
from plugins.SinaDLoader import DLoader

plugin_class = (
AolAmpX, 
BaiduBar, 
CGAgent, 
DLoader)


plugin_method = [
'AolAmpXAppendFileToPlayList', 
'BaiduBarToolDloadDS', 
'CGAgentCreateChinagames', 
'DownloaderDLoaderDownloadAndInstall']