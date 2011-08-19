Before using AxMock, please learn the licence of our applicaiton.
Thank Ian Welch, Van Lam Le, Jianwei Zhuge and Chengyu Song for their contribution and suggestions.

Special thanks to Rujia Liu for his concerning all the time. :P

*** How to use AxMock ***

1. Run DummyRegister.py
   python DummyRegister.py

2. Open Manager\AxMockManager.sln with VS2008 and compile. The generated dll will be in Manager\Debug directory

3. Move Manager\Debug\AxMockManager.dll to bin directory

4. In bin directory, execute the following shell command (this will inject our dll into Internet Explorer):

   withdll.exe /d:AxMockManager.dll c:\Program Files\Internet Explorer\iexplore.exe
   
   You can see a new IE process created, and the alerting message will be logged in AxMockLog.txt

   For more information about withdll.exe, just run it with no options.
