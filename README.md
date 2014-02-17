linux-802.15.4-sniffer
======================

The aim of this project is to create a linux based 802.15.4/Zigbee sniffer without the need of any firmware or a microcontroller. The hardware used is Microchip's MRF24J40MA 2.4 GHz 802.15.4 transceiver over a FTDI USB-SPI bridge. The code to configure and capture packets from the radio is written in python and piped to wireshark for parsing and viewing.




## Required Hardware

* [FT232H](http://www.ftdichip.com/Products/ICs/FT232H.htm) or [FT2232H](http://www.ftdichip.com/Products/ICs/FT2232H.html) based breakout board. I used the [UM232H-B-WE](http://www.mouser.com/ProductDetail/FTDI/UM232H-B-WE/?qs=ti%252bTZKs0nFjsDpn/xbvU5w==)
* [Microchip's MRF24J40MA 802.15.4 Transceiver](http://www.mouser.com/new/microchip/MRF24J40MA/)


![alt text](https://raw.github.com/mbains/linux-802.15.4-sniffer/master/resources/mrf24j40ma.png "Hardware after assembly")


## Required Software
* [libmpsse](https://code.google.com/p/libmpsse/)
* Wireshark


## Running:

python mrf.py  &lt;IEEE 2.4GHz Channel&gt; 


![alt text](https://raw.github.com/mbains/linux-802.15.4-sniffer/master/resources/zigbee_sniff.png "Wireshark sniff")
