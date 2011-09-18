from plugins.AolAmpX import AolAmpX
from plugins.CGAgent import CGAgent
from plugins.BaiduBar import BaiduBar
from plugins.SinaDLoader import DLoader
from plugins.KingView import KingView

plugin_class = (AolAmpX, BaiduBar, CGAgent, DLoader, KingView)
plugin_method = ['BaiduBarToolDloadDS', 'AolAmpXAppendFileToPlayList', 'CGAgentCreateChinagames', 'DownloaderDLoaderDownloadAndInstall', 'KingViewValidateUser']