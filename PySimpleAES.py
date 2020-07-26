#!/usr/bin/env python
# -*- coding: utf-8 -*-
#author: jimvon
#date: 2020/07/13-11:56:15

HELP='''
Backstage (PySimpleAES.py is a backstage python class. ); 
to use this application, please go main.py;
to just see runtime example, please go test.py;

sample.enc = AES+ofb+16+iv(16B)+enc(msg)+enc(padding); 

'''

import math
import time
import os
import re
import base64
from Crypto.Cipher import AES
from Crypto import Random as CryptoRandom


def warn(info):
    '''key=info
    if (type(key)==type('str')):
            key=key.encode('utf-8')
    if (type(key)==type(b'bytes')):
        key=key+b'\0'*(block_size-len(key)%16)
    else:
        warn('bad key')
        key=b'123'+b'\0'*13
    s=info'''
    print(info)
def getDefaultDict():
#header="AES%3s%2d%s"    #%3s=ofb/cbc/cfb/ecb, %2d=16/24/32, %s=iv
    defaultDict={'block_size':16, 'defaultKey':'123', 'mode':'ofb', 'iv':b'', 'pad':b'\0', 'header':b"AES%3s%2d%s", 'headerSize':64, 'charset':'utf-8'}
    return defaultDict

class PySimpleAES:
    '''
    block_size = 16 or 24 or 32, or 128 or 192 or 256;	default 16;
    key is a str or bytes, len(key) <= block_size;		not default;
    smode = 'ecb' or 'cbc' or 'cfb' or 'ofb';		default 'ofb';
    mode = __modes[smode];	
    iv is a bytes, len(iv) == block_size;			default Random.new().read(block_size);
    '''
    def __init__(self, key, block_size=getDefaultDict()['block_size'], mode=getDefaultDict()['mode'], iv=getDefaultDict()['iv']):
        (key, block_size, mode, iv)=self.__checkPySimpleAESArgs(key, block_size, mode, iv)
        AES.block_size=block_size
        self.block_size=block_size
        self.key=self.padding(key)
        self.smode=mode
        self.mode=PySimpleAES.modes().get(mode)
        if (len(iv)==0):
            self.iv=CryptoRandom.new().read(block_size)
        else:
            self.iv=self.padding(iv)
    def __checkPySimpleAESArgs(self,key, block_size, mode, iv):
        #to deal block_size
        if (block_size not in [16,24,32,128,192,256]):
            block_size=getDefaultDict()['block_size']
            warn('block_size ValueError, use default block_size: %d'%block_size)
        if (block_size>=128):
            block_size=(block_size>>3)
        #to deal key
        if (type(key)!=type('str') and type(key)!=type(b'bytes')):
            key=getDefaultDict()['defaultKey']
            warn('Key TypeError, use default key: %s'%(key))
        if (type(key)==type('str') and len(key.encode(getDefaultDict()['charset']))>block_size):
            warn('key "%s" is too long, so only use first %d Bytes'%(key,block_size))
            key=key.encode(getDefaultDict()['charset'])[:block_size]
        elif(type(key)==type(b'bytes') and len(key)>block_size):
            warn('key "%s" is too long, so only use first %d Bytes'%(key,block_size))
            key=key[:block_size]
        #to deal mode
        mode=mode.lower()
        if (mode not in PySimpleAES.modes().keys()):
            mode=getDefaultDict()['mode']
            warn('no such mode, use default mode: %s'%mode)
        #to deal iv
        if (mode=='ecb' and (iv!=None and len(iv)>0)):
            warn('ECB mode not need iv')
        if (mode!='ecb'):
            if (iv==None  or (type(iv)!=type('str') and type(iv)!=type(b'bytes')) or len(iv)>block_size):
                iv=b''
                warn('bad iv, use default iv: Random.new().read(AES.block_size)')
            elif (len(iv)==0):
                pass
            else:
                if (type(iv)==type('str')):
                    iv=iv.encode(getDefaultDict()['charset'])[:block_size]
                iv=self.padding(iv)
                warn('iv = "%s"'%iv)
        return (key, block_size, mode, iv)
    @staticmethod
    def modes():
        return {'ecb':AES.MODE_ECB, 'cbc':AES.MODE_CBC, 'cfb':AES.MODE_CFB, 'ofb':AES.MODE_OFB}
    @staticmethod
    def padding(msg,block_size=AES.block_size,pad=getDefaultDict()['pad']):
        if (type(msg)==type('str')):
            pas=msg.encode(getDefaultDict()['charset'])
        else:
            pas=msg
        if (type(pas)==type(b'bytes')):
            padlen=block_size-len(pas)%block_size
            if (len(pas)==0 or padlen<block_size):
                pas=pas+(pad*padlen)
            return pas
        else:
            return b''
    @staticmethod
    def formHeader(mode,block_size,iv):
        header=getDefaultDict()['header']%(mode.encode(getDefaultDict()['charset']),block_size,iv)
        headerSize=getDefaultDict()['headerSize']
        if (len(header)>headerSize):
            warn("The default headerSize must be bigger, so this enc will be no ivInfo")
            return b''
        header+=getDefaultDict()['pad']*(headerSize-len(header))
        return header
    @staticmethod
    def deHeader(header, pattern=''):
    #pattern: if not use the default header("AES%3s%2d%s"), you have to assign one.ggsp22.taso360
        if (len(pattern)==0):
            pattern=br'AES(\w{3})(\d{2})(.+)'
        headgroup=re.match(pattern,header,re.DOTALL).groups()
        mode=headgroup[0].decode(getDefaultDict()['charset'])
        block_size=int(headgroup[1])
        iv=headgroup[2][:block_size]
        return (mode,block_size,iv)
        
    def encText(self, msg, addIvInfo=True):
        if (self.smode!='ecb'):
            cipher=AES.new(self.key,self.mode,self.iv)
        else:
            cipher=AES.new(self.key,self.mode)
            addIvInfo=False
        bmsg=self.padding(msg)
        enc=cipher.encrypt(bmsg)
        if (addIvInfo):
            header=self.formHeader(self.smode,self.block_size,self.iv)
            enc=header+enc
        return base64.b64encode(enc)
    def decText(self, enc, pad=getDefaultDict()['pad']):
        benc=base64.b64decode(enc)
        if (self.smode!='ecb'):
            if (benc.startswith(b'AES')):
                headerSize=getDefaultDict()['headerSize']
                encheader=benc[:headerSize]
                (encmode,encblock_size,enciv)=self.deHeader(encheader)
                AES.block_size=encblock_size
                cipher=AES.new(self.key,PySimpleAES.modes()[encmode],enciv)
                benc=benc[headerSize:]
            else:
                cipher=AES.new(self.key,self.mode,self.iv)
        else:
            cipher=AES.new(self.key,self.mode)
        dec=cipher.decrypt(benc)
        dec=dec.rstrip(pad) #May do damage to msg
        dec=dec.decode(getDefaultDict()['charset'])
        return dec
    @staticmethod
    def encFile(filePathName, outFile='', key='123',  iv=b'', pad=b'\0', mode='ofb', block_size=16):
    #without error tollerance
        instream=open(filePathName,'rb')
        mode=mode.lower()
        if (mode=='cbc'):
            iv=b''
            cipher=AES.new(PySimpleAES.padding(key,pad=pad), PySimpleAES.modes()[mode])
        else:
            if (len(iv)!=block_size):
                iv=CryptoRandom.new().read(block_size)
                warn('iv=%s'%iv)
            cipher=AES.new(PySimpleAES.padding(key,pad=pad), PySimpleAES.modes()[mode], iv)
        if (len(outFile)==0):
            outFile='enc'+os.sep+('cipher_'+time.strftime('%Y%m%d%H%M%S')+'.enc')
        read_size=1024*4
        vals=-1
        with open(outFile,'wb') as outstream:
            if (mode!='cbc'):
                header=PySimpleAES.formHeader(mode,block_size,iv)
                outstream.write(header)
            isNBreak=True
            while (isNBreak):
                msg=instream.read(read_size)
                if (len(msg)<read_size):
                    msg=PySimpleAES.padding(msg,pad=pad)
                    isNBreak=False
                enc=cipher.encrypt(msg)
                vals=outstream.write(enc)
        instream.close()
        return vals
    @staticmethod
    def decFile(filePathName, outFile='', key='123',  iv=b'', pad=b'\0', mode='ofb', block_size=16):
    #without error tollerance
        instream=open(filePathName,'rb')
        mode=mode.lower()
        headerSize=getDefaultDict()['headerSize']
        if (mode=='cbc'):
            iv=b''
            cipher=AES.new(PySimpleAES.padding(key,pad=pad), PySimpleAES.modes()[mode])
        else:
            if (len(iv)!=block_size):
                ###iv=CryptoRandom.new().read(block_size)
                header=instream.read(headerSize)
                if (not header.startswith(b'AES')):
                    warn("not header.startswith(b'AES') == True")
                    warn('bad .enc file, wrong format')
                (mode,encblock_size,iv)=PySimpleAES.deHeader(header)
                block_size=encblock_size
                AES.block_size=encblock_size
            cipher=AES.new(PySimpleAES.padding(key,pad=pad), PySimpleAES.modes()[mode], iv)
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
                    dec.rstrip(pad) #danger
                    vals=outstream.write(dec)
                    break
                dec=cipher.decrypt(encmsg)
                vals=outstream.write(dec)
                encmsg=nextmsg
        instream.close()
        return vals


if (__name__=='__main__'):
    print(HELP)
    input("\nPress ENTER to exit...")

