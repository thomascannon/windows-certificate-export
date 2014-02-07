import win32crypt
open("priv.dec", 'wb').write(win32crypt.CryptUnprotectData(open("priv.enc", 'rb').read(),None,None,None,0)[1])
