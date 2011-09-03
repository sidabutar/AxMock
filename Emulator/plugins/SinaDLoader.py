# Sina DLoader Class ActiveX Control 'DonwloadAndInstall'
# Method Arbitrary File Download Vulnerability
class DLoader:
    def DownloaderDLoaderDownloadAndInstall(self, url):
        file = open("AxMockLog.txt", "a")
		file.write('Downloader.Dloader ActiveX Vulnerability in DownloadAndInstall method \n')
        file.write('URL: ' + url)
        file.close()