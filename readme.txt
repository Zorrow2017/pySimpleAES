Python3; Require pycryptodome; Poor error tolerance; 

PySimpleAES.py

__init__(key="123"); 
encText("text");
decText("XXX");
encFile("fileIn.mp3", "fileOut.enc");
decFile("fileOut.enc", "file.dec");

can encrypt data by AES(ECB, CBC, OFB);

usage: 
(cmd: pip install pycryptodome)
import PySimpleAES
cipher = PySimpleAES(key = '123')
simple = 'so simple'
encText = cipher.encText(simple)
print(encText)
print(cipher.decText(encText))
with open("simple.htm", 'wb') as f:
    f.write(b'AES so simple\r\n\t  \\end   ')
cipher.encFile("simple.htm", "simple.enc")
PySimpleAES.decFile("simple.enc", "simple.dec", key='123')

shortages: 
must import Crypto.Cipher.AES(pycryptodome), and maybe Crypto.Random(pycryptodome); 
test.py and main.py is not exist temporarily; 
try-catch makes PySimpleAES.py not simple; 
try-catch cover only a few bugs; 
 'Sun Jul 26 23:55:57 2020'


