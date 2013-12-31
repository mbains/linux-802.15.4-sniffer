#!/usr/bin/env python
# -*- coding: utf-8 -*- 
from array import array
import os
import sys
import struct
import errno
import time
from pcapd.pcapdump import PcapDumper

from mpsse import *


class MrfRxStatus(object):
    def __init__(self):
        self.rx_data = array('B')
        self.rx_rawdata = array('B')
        self.lqi = None
        self.rssi = None
        self.frame_length = 0

    def rx_datalength(self):
        return self.frame_length - Mrf24j40.BYTES_OVERHEAD

    def __str__(self):
        return "rx_data: %s, lqi :%s, rssi:%s, %s" % (self.rx_data.tostring(),
                                                      self.lqi, self.rssi, self.rx_rawdata)

class MrfTxStatus(object):
    def __init__(self):
        self.success = None
        self.retries = None
        self.channel_busy = None
    

class Mrf24j40(object):
    MRF_RFCON0 = 0x200
    MRF_RXMCR = 0x00
    MRF_PANIDL = 0x01
    MRF_PANIDH = 0x02
    MRF_SADRL = 0x03
    MRF_SADRH = 0x04
    MRF_EADR0 = 0x05
    MRF_EADR1 = 0x06
    MRF_EADR2 = 0x07
    MRF_EADR3 = 0x08
    MRF_EADR4 = 0x09
    MRF_EADR5 = 0x0A
    MRF_EADR6 = 0x0B
    MRF_EADR7 = 0x0C
    MRF_RXFLUSH = 0x0D
    MRF_ORDER = 0x10
    MRF_TXMCR = 0x11
    MRF_ACKTMOUT = 0x12
    MRF_ESLOTG1 = 0x13
    MRF_SYMTICKL = 0x14
    MRF_SYMTICKH = 0x15
    MRF_PACON0 = 0x16
    MRF_PACON1 = 0x17
    MRF_PACON2 = 0x18

    MRF_TXBCON0 = 0x1A

    MRF_TXNCON = 0x1B
    MRF_TXNTRIG = 0
    MRF_TXNSECEN = 1
    MRF_TXNACKREQ = 2
    MRF_INDIRECT = 3
    MRF_FPSTAT = 4

    MRF_TXG1CON = 0x1C
    MRF_TXG2CON = 0x1D
    MRF_ESLOTG23 = 0x1E
    MRF_ESLOTG45 = 0x1F
    MRF_ESLOTG67 = 0x20
    MRF_TXPEND = 0x21
    MRF_WAKECON = 0x22
    MRF_FRMOFFSET = 0x23

    MRF_TXSTAT = 0x24
    TXNRETRY1 = 7
    TXNRETRY0 = 6
    CCAFAIL = 5
    TXG2FNT = 4
    TXG1FNT = 3
    TXG2STAT = 2
    TXG1STAT = 1
    TXNSTAT = 0

    MRF_TXBCON1 = 0x25
    MRF_GATECLK = 0x26
    MRF_TXTIME = 0x27
    MRF_HSYMTMRL = 0x28
    MRF_HSYMTMRH = 0x29
    MRF_SOFTRST = 0x2A

    MRF_SECCON0 = 0x2C
    MRF_SECCON1 = 0x2D
    MRF_TXSTBL = 0x2E

    MRF_RXSR = 0x30
    MRF_INTSTAT = 0x31
    MRF_INTCON = 0x32
    MRF_GPIO = 0x33
    MRF_TRISGPIO = 0x34
    MRF_SLPACK = 0x35
    MRF_RFCTL = 0x36
    MRF_SECCR2 = 0x37
    MRF_BBREG0 = 0x38
    MRF_BBREG1 = 0x39
    MRF_BBREG2 = 0x3A
    MRF_BBREG3 = 0x3B
    MRF_BBREG4 = 0x3C

    MRF_BBREG6 = 0x3E
    MRF_CCAEDTH = 0x3F

    MRF_RFCON0 = 0x200
    MRF_RFCON1 = 0x201
    MRF_RFCON2 = 0x202
    MRF_RFCON3 = 0x203
    MRF_RFCON5 = 0x205
    MRF_RFCON6 = 0x206
    MRF_RFCON7 = 0x207
    MRF_RFCON8 = 0x208
    MRF_SLPCAL0 = 0x209
    MRF_SLPCAL1 = 0x20A
    MRF_SLPCAL2 = 0x20B
    MRF_RSSI = 0x210
    MRF_SLPCON0 = 0x211
    MRF_SLPCON1 = 0x220
    MRF_WAKETIMEL = 0x222
    MRF_WAKETIMEH = 0x223
    MRF_REMCNTL = 0x224
    MRF_REMCNTH = 0x225
    MRF_MAINCNT0 = 0x226
    MRF_MAINCNT1 = 0x227
    MRF_MAINCNT2 = 0x228
    MRF_MAINCNT3 = 0x229
    MRF_TESTMODE = 0x22F
    MRF_ASSOEADR1 = 0x231
    MRF_ASSOEADR2 = 0x232
    MRF_ASSOEADR3 = 0x233
    MRF_ASSOEADR4 = 0x234
    MRF_ASSOEADR5 = 0x235
    MRF_ASSOEADR6 = 0x236
    MRF_ASSOEADR7 = 0x237
    MRF_ASSOSADR0 = 0x238
    MRF_ASSOSADR1 = 0x239
    MRF_UPNONCE0 = 0x240
    MRF_UPNONCE1 = 0x241
    MRF_UPNONCE2 = 0x242
    MRF_UPNONCE3 = 0x243
    MRF_UPNONCE4 = 0x244
    MRF_UPNONCE5 = 0x245
    MRF_UPNONCE6 = 0x246
    MRF_UPNONCE7 = 0x247
    MRF_UPNONCE8 = 0x248
    MRF_UPNONCE9 = 0x249
    MRF_UPNONCE10 = 0x24A
    MRF_UPNONCE11 = 0x24B
    MRF_UPNONCE12 = 0x24C

    MRF_I_RXIF = 0b00001000
    MRF_I_TXNIF = 0b00000001

    BYTES_MHR = 9
    BYTES_FCS = 2
    BYTES_OVERHEAD = (BYTES_MHR + BYTES_FCS)
    
    def __init__(self, bufferPhysical=False, channel=12):
        self._bufferPhysicalLayer = bufferPhysical
        self.rx_buf = array('B')
        self.mp = MPSSE(SPI0, ONE_MHZ, MSB)
        self.write_short(self.MRF_PACON2, 0x98) # – Initialize FIFOEN = 1 and TXONTS = 0x6.
        self.write_short(self.MRF_TXSTBL, 0x95) #  – Initialize RFSTBL = 0x9.


        self.write_long(self.MRF_RFCON0, 0x03) # – Initialize RFOPT = 0x03.
        self.write_long(self.MRF_RFCON1, 0x01) # – Initialize VCOOPT = 0x02.
        self.write_long(self.MRF_RFCON2, 0x80) # – Enable PLL (PLLEN = 1).
        self.write_long(self.MRF_RFCON6, 0x90) # – Initialize TXFIL = 1 and 20MRECVR = 1.
        self.write_long(self.MRF_RFCON7, 0x80) # – Initialize SLPCLKSEL = 0x2 (100 kHz Internal oscillator).
        self.write_long(self.MRF_RFCON8, 0x10) # – Initialize RFVCO = 1.
        self.write_long(self.MRF_SLPCON1, 0x21) # – Initialize CLKOUTEN = 1 and SLPCLKDIV = 0x01.
        #Configuration for nonbeacon-enabled devices (see Section 3.8 “Beacon-Enabled and
        #Nonbeacon-Enabled Networks”):
        self.write_short(self.MRF_BBREG2, 0x80) # Set CCA mode to ED
        self.write_short(self.MRF_CCAEDTH, 0x60) # – Set CCA ED threshold.
        self.write_short(self.MRF_BBREG6, 0x40); # – Set appended RSSI value to RXFIFO.
        self.set_channel(channel);
        #max power is by default.. just leave it...
        #Set transmitter power - See “REGISTER 2-62: RF CONTROL 3 REGISTER (ADDRESS: 0x203)”.
        self.write_short(self.MRF_RFCTL, 0x04) # – Reset RF state machine.
        self.write_short(self.MRF_RFCTL, 0x00) # part 2

        self.rxStatusQueue = []
        self.txStatusQueue = []
        print "mrf24j40 driver initialized on channel ", channel



    def write_short(self, address, value):
        self.mp.Start()
        val = struct.pack('BB', (address << 1) | 1, value)
        self.mp.Write(val)
        self.mp.Stop()


    def read_short(self, address):
        self.mp.Start()
        self.mp.Write(struct.pack('B', (address << 1)))
        data = self.mp.Read(1)
        self.mp.Stop()
        return struct.unpack('B', data)[0]

    def write_long(self, address, data):
        self.mp.Start()
        addr_tx = (((1 << 11) | (address << 1) | 1) << 4)
        self.mp.Write(struct.pack('>HB', addr_tx, data))
        self.mp.Stop()

    def read_long(self, address):
        self.mp.Start()
        addr_tx = (((1 << 11) | (address << 1)) << 4);
        self.mp.Write(struct.pack('>H', addr_tx))
        data = self.mp.Read(1)
        self.mp.Stop()
        return struct.unpack('B', data)[0]

    def read_long_bytes(self, address, count):
        ''' For reading packets, the MRF can continue to send frame while
        incrementing the address'''
        print "reading nbytes:", count
        data = array('B')
        self.mp.Start()
        addr_tx = (((1 << 11) | (address << 1)) << 4);
        self.mp.Write(struct.pack('>H', addr_tx))
        data.fromstring(self.mp.Read(count))
        self.mp.Stop()
        return data

    def set_channel(self, channel):
        self.write_long(self.MRF_RFCON0, (((channel - 11) << 4) | 0x03))

    def verify(self):
        self.write_long(self.MRF_RFCON0, 0x3)
        print '%r' % self.read_long(self.MRF_RFCON0)

    def rx_disable(self):
        self.write_short(self.MRF_BBREG1, 0x04)

    def rx_enable(self):
        self.write_short(self.MRF_BBREG1, 0)

    def setpan(self, panid):
        self.write_short(self.MRF_PANIDH, panid >> 8)
        self.write_short(self.MRF_PANIDL, panid & 0xff)

    def getpan(self):
        panh = self.read_short(self.MRF_PANIDH)
        return panh << 8 | self.read_short(self.MRF_PANIDL)

    def set_short_addr(self, address):
        self.write_short(self.MRF_SADRH, address >> 8)
        self.write_short(self.MRF_SADRL, address & 0xFF)

    def set_promiscuous(self, enabled):
        bit = 1 if enabled else 0
        self.write_short(self.MRF_RXMCR, bit);


    def interrupt_handler(self):
        last_interrupt = self.read_short(self.MRF_INTSTAT)
        if last_interrupt & self.MRF_I_RXIF:
            rx_info = MrfRxStatus()
            self.rx_disable()

            rx_info.frame_length = self.read_long(0x300)
            #read start of rxfifo for, has 2 bytes more added by FCS. frame_length = m + n + 2
            if self._bufferPhysicalLayer:
                rx_info.rx_rawdata = self.read_long_bytes(0x301, rx_info.frame_length)

#buffer data
            #rx_info.rx_data = self.read_long_bytes(0x301 + self.BYTES_MHR, rx_info.rx_datalength())

            rx_info.lqi = self.read_long(0x301 + rx_info.frame_length)
            rx_info.rssi = self.read_long(0x301 + rx_info.frame_length + 1)
            self.rxStatusQueue.append(rx_info)
            self.rx_enable()
            
        if last_interrupt & self.MRF_I_TXNIF:
            tx_info = MrfTxStatus()
            stat_reg = self.read_short(self.MRF_TXSTAT)
            tx_info.success = not stat_reg & 0x1F
            tx_info.retries = stat_reg >> 6
            tx_info.channel_busy = stat_reg & (1 << self.CCAFAIL)
            self.txStatusQueue.append(tx_info)



            

if __name__ == '__main__':
    pipename = '/tmp/wiresharkpipe'
    #os.system('rm -f ' + pipename)
    try:
        os.mkfifo(pipename) #default mode 0666 (octal)
    except OSError, e:
        if e.errno != errno.EEXIST:    
            print "Failed to create FIFO: %s" % e
            sys.exit(-1)
            
    rcode = os.fork()
    if rcode == 0:
        os.execlp('wireshark', 'wireshark', '-k', '-i', pipename)

    dumper = PcapDumper(195, pipename)
    mrf = Mrf24j40(True, int(sys.argv[-1]))
    mrf.setpan(0xcafe)
    mrf.set_short_addr(0x100)
    mrf.set_promiscuous(True)
    try:
        while True:
            #time.sleep(0.1)
            #no interrupts, poll for now
            mrf.interrupt_handler()
            QLen = len(mrf.rxStatusQueue)
            if QLen:
                pkt = mrf.rxStatusQueue.pop(0)
                print pkt
                dumper.pcap_dump(pkt.rx_rawdata.tostring())
    except KeyboardInterrupt, e:
        dumper.close()
    #for msg in mrf.rxStatusQueue:
        #    print msg.rx_data.tostring()
