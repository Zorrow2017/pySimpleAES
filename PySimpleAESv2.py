#!/usr/bin/env python
# -*- coding: utf-8 -*-
#author: jimvon
#date: 2020/07/13-11:56:15

HELP='''
Backstage (PySimpleAESv2.py is a backstage python class. ); 
to use this application, please go main.py;
to just see runtime example, please go test.py;

sample.enc = AES+ofb+16+iv(16B)+enc(msg)+enc(padding); 
this file has no complex try-except, simple and readable. 

IMPORTANT:
Compare with PySimpleAES.py, PySimpleAESv2.py is 
    easy to read for programmers, 
    more reliable function of encText() and encFile(),
    add a simple cmd(REPL) for encText() and decText();
'''

import math
import time
import os
import re
import base64
from Crypto.Cipher import AES
from Crypto import Random as CryptoRandom


def warn(info):
    print(info)
defaultd={'charset':'utf-8', 'key':'123', 'block_size':16, 'mode':'cbc', 'iv':b'0123456789abcdef', 'pad':b'\0', 'header':b"AES(headerSize=%3d)%3s%2d%s", 'headerSize':64}

class PySimpleAESv2:
    '''
    block_size = 16 or 24 or 32, or 128 or 192 or 256;	default 16;
    key is a str or bytes, len(key) <= block_size;		not default;
    modeStr = 'ecb' or 'cbc' or 'cfb' or 'ofb';		default 'cbc';
    mode = modes()[modeStr];	
    iv is a bytes, len(iv) == block_size;			default Random.new().read(block_size);
    '''
    def __init__(self, key=defaultd['key'], block_size=defaultd['block_size'], mode=defaultd['mode'], iv=defaultd['iv']):
        if (block_size>=128):
            block_size=(block_size>>3)
        AES.block_size=block_size
        self.block_size=block_size
        self.key=self.padding(key)
        self.modeStr=mode
        self.mode=PySimpleAESv2.modes()[mode]
        self.iv=self.padding(iv, block_size=16)

    @staticmethod
    def modes():
        return {'ecb':AES.MODE_ECB, 'cbc':AES.MODE_CBC, 'cfb':AES.MODE_CFB, 'ofb':AES.MODE_OFB}
    @staticmethod
    def padding(msg,block_size=AES.block_size,pad=defaultd['pad']):
        if (type(msg)!=type('str') and type(msg)!=type(b'bytes')):
            return b''
        bytemsg=msg
        if (type(msg)==type('str')):
            bytemsg=msg.encode(defaultd['charset'])
        padlen=block_size-len(bytemsg)%block_size
        if (len(bytemsg)==0 or padlen<block_size):
            bytemsg=bytemsg+(pad*padlen)
        return bytemsg
    @staticmethod
    def formHeader(mode,block_size,iv,padlen=0):
        headerSize=defaultd['headerSize']
        header=defaultd['header']%(headerSize,mode.encode(defaultd['charset']),block_size,iv)
        if (padlen):
            #will be used for dec.rstrip(pad)
            header+=b'%2d'%padlen
        header+=defaultd['pad']*(headerSize-len(header))
        return header
    @staticmethod
    def deHeader(header, pattern='', padlen=False):
    #pattern: if not use the default header("AES(headerSize=%3d)%3s%2d%s"), you have to assign one.
        if (len(pattern)==0):
            pattern=br'AES\(headerSize=([\d ]{3})\)(\w{3})(\d{2})(.+)'
        headgroup=re.match(pattern,header,re.DOTALL).groups()
        headerSize=int(headgroup[0])
        mode=headgroup[1].decode(defaultd['charset'])
        block_size=int(headgroup[2])
        iv=headgroup[3][:16]
        if (padlen):
            padlen=int(headgroup[3][16:18])
            return (headerSize,mode,block_size,iv,padlen)
        return (headerSize,mode,block_size,iv)
        
    def encText(self, msg, randomIv=False, addHeader=False):
        if (self.modeStr=='ecb'):
            cipher=AES.new(self.key,self.mode)
            addHeader=False
        else:
            if (randomIv):
                eiv=CryptoRandom.new().read(16)
                addHeader=True
            else:
                eiv=self.iv
            cipher=AES.new(self.key,self.mode,eiv)
        bmsg=self.padding(msg)
        enc=cipher.encrypt(bmsg)
        if (addHeader):
            header=self.formHeader(self.modeStr,self.block_size,self.iv)
            enc=header+enc
        return base64.b64encode(enc)
    def decText(self, enc, pad=defaultd['pad'], doStrip=True):
        benc=base64.b64decode(enc)
        if (self.modeStr=='ecb'):
            cipher=AES.new(self.key,self.mode)
        else:
            if (benc.startswith(b'AES')):
                headerSize=defaultd['headerSize']
                minHeaderSize=48
                encheader=benc[:minHeaderSize]
                (headerSize,encmode,encblock_size,enciv)=self.deHeader(encheader)
                AES.block_size=encblock_size
                cipher=AES.new(self.key,PySimpleAESv2.modes()[encmode],enciv)
                benc=benc[headerSize:]
            else:
                cipher=AES.new(self.key,self.mode,self.iv)
        dec=cipher.decrypt(benc)
        decstrip=dec.rstrip(pad) #May do damage to msg
        try:
            decstrip=decstrip.decode(defaultd['charset'])
        except:
            warn()
            doStrip=False
        if (doStrip):
            return decstrip
        return dec
    @staticmethod
    def encFile(filePathName, outFile='', key='123',  iv=b'0123456789abcdef', pad=b'\0', mode='ofb', block_size=16):
    #without error tollerance
        instream=open(filePathName,'rb')
        mode=mode.lower()
        if (mode=='ecb'):
            iv=b''
            cipher=AES.new(PySimpleAESv2.padding(key,pad=pad), PySimpleAESv2.modes()[mode])
        else:
            if (len(iv)!=block_size):
                iv=CryptoRandom.new().read(16)
                #warn('iv=%s'%iv)
            cipher=AES.new(PySimpleAESv2.padding(key,pad=pad), PySimpleAESv2.modes()[mode], iv)
        if (len(outFile)==0):
            outFile='enc'+os.sep+('cipher_'+time.strftime('%Y%m%d%H%M%S')+'.enc')
        read_size=1024*4
        vals=-1
        with open(outFile,'wb') as outstream:
            if (mode!='ecb'):
                header=PySimpleAESv2.formHeader(mode,block_size,iv)
                outstream.write(header)
            isNBreak=True
            while (isNBreak):
                msg=instream.read(read_size)
                if (len(msg)<read_size):
                    padlen=len(msg)
                    msg=PySimpleAESv2.padding(msg,pad=pad)
                    padlen=len(msg)-padlen
                    outstream.seek(len('AES(headerSize= 64)ofb160123456789abcdef'))
                    outstream.write(b'%2d'%padlen)
                    outstream.seek(0,2)  #seek to end of the file
                    isNBreak=False
                enc=cipher.encrypt(msg)
                vals=outstream.write(enc)
        instream.close()
        return vals
    @staticmethod
    def decFile(filePathName, outFile='', key='123',  iv=b'0123456789abcdef', pad=b'\0', mode='ofb', block_size=16):
    #without error tollerance
        instream=open(filePathName,'rb')
        mode=mode.lower()
        headerSize=defaultd['headerSize']
        minHeaderSize=48
        if (mode=='ecb'):
            iv=b''
            cipher=AES.new(PySimpleAESv2.padding(key,pad=pad), PySimpleAESv2.modes()[mode])
        else:
            if (len(iv)!=block_size or iv==b'0123456789abcdef'):
                ###iv=CryptoRandom.new().read(block_size)
                header=instream.read(minHeaderSize)
                if (not header.startswith(b'AES')):
                    iv=b'0123456789abcdef'
                    instream.seek(0)
                    #warn("not header.startswith(b'AES') == True")
                else:
                    (headerSize,mode,encblock_size,iv,padlen)=PySimpleAESv2.deHeader(header,padlen=1)
                    vals=instream.read(headerSize-minHeaderSize)
                    block_size=encblock_size
                    AES.block_size=encblock_size
            cipher=AES.new(PySimpleAESv2.padding(key,pad=pad), PySimpleAESv2.modes()[mode], iv)
        if (len(outFile)==0):
            outFile='msg_dec'+os.sep+('dec_'+time.strftime('%Y%m%d%H%M%S')+'.dec')
        read_size=1024*4
        vals=-1
        with open(outFile,'wb') as outstream:
            encmsg=instream.read(read_size)
            while (True):
                nextmsg=instream.read(read_size)
                if (len(nextmsg)<read_size):
                    dec=cipher.decrypt(encmsg)+cipher.decrypt(nextmsg)
                    #dec.rstrip(pad) #danger
                    if (padlen):
                        dec=dec[:-padlen]
                    vals=outstream.write(dec)
                    break
                dec=cipher.decrypt(encmsg)
                vals=outstream.write(dec)
                encmsg=nextmsg
        instream.close()
        return vals


if (__name__=='__main__'):
    print(HELP)
    while (1):
        cp=PySimpleAESv2('123',mode='cbc',iv=b'0123456789abcdef')
        text=input('\ntext to encrypt with key=123 (or "dec XT1XVmJURjFZAfShTw3ITA==" to decrypt)\n')
        if (re.match('^0+$', text.strip())):
            break
        if (text.startswith('dec')):
            print(cp.decText(text[3:].strip()))
            continue
        enc=cp.encText(text,addHeader=False)
        print(enc.decode('utf-8'))
        print('input 0000 means to exit')		
    input("\nPress ENTER to exit...")

