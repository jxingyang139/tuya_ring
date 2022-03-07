#!/usr/bin/env python3
# coding=utf-8

'''
* Copyright (c) 2020 HiSilicon (Shanghai) Technologies CO., LIMITED.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* Description: License write demo in factory mode.
* in order to run this script, user should enter windows cmd and install python serial module:
* pip install serial
* pip install pyserial
'''

import time, serial
from struct import *
import binascii

licence_path = 'D:\\license.bin'
com_number = 'COM9'
baudrate = 115200

# start license transfer.
ser = serial.Serial(com_number, baudrate, timeout=2)
ser.write('AT+WRITE=2048\r\n'.encode("gbk"))
print(ser.readline())
ser.close()
time.sleep(0.2)

i = 0
with open(licence_path, 'rb') as file:
    while 1:
        c = file.read(1)
        # convert byte to hex；
        str_c = str(binascii.b2a_hex(c))[2:-1]
        # print(str(binascii.b2a_hex(c))[2:-1])
        if not c:
            break
        ser = serial.Serial(com_number, baudrate, timeout=1)
        ser.write(bytes().fromhex(str_c))# convert hext to byte
        #if i % 16 == 0:
        #    time.sleep(0.01)# wait per 16 btye.
        time.sleep(0.002)# wait 2ms per byte for compatible defective usb-uart chip.

        i += 1
        ser.close()
    file.close()

# print license trans result log.
ser = serial.Serial(com_number, baudrate, timeout=2)
print(ser.readline())
print(ser.readline())
ser.close()

# switch from factory mode to normal mode.
time.sleep(0.2)
ser = serial.Serial(com_number, baudrate, timeout=2)
ser.write('AT+FTM=0\r\n'.encode("gbk"))
print(ser.readline())
print(ser.readline())
ser.close()

# reset module.
time.sleep(0.2)
ser = serial.Serial(com_number, baudrate, timeout=2)
ser.write('AT+RST=0\r\n'.encode("gbk"))
print(ser.readline())
print(ser.readline())
ser.close()
