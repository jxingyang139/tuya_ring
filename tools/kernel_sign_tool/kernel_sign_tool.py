#!/usr/bin/env python3
# coding=utf-8

'''
* Copyright (C) HiSilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
* Description: hupg main build scripts
'''

import os
import time
import sys
import sign_upg_file as MAKE_IMAGE
import shutil
import struct
from hi_config_parser import usr_cfg_main
from hi_config_parser import sys_cfg_main

root_path = os.path.join(os.getcwd(), '..', '..') if getattr(sys, 'frozen', False) else os.path.join(os.path.dirname(__file__), '..', '..')
print('execute ota_builder with exe...') if getattr(sys, 'frozen', False) else print('execute ota_builder with python...')
class ImageBuild:
    def __init__(self, app_name="Hi3861_demo", sign_alg=0x3F, kernel_file_ver=0, flashboot_file_ver=0, chip_product="Hi3861", usr_realtive_output='', ota_mode=0):
        self.__app_name = app_name
        self.__bootBinPath = os.path.join(root_path, usr_realtive_output, 'build', 'flashboot', 'Hi3861_flash_boot.bin')
        self.__kernelBinPath = os.path.join(root_path, usr_realtive_output, 'output', 'bin', '%s_non_rom.bin'%self.__app_name)
        self.__normalNvPath = os.path.join(root_path, 'build', 'build_tmp', 'nv', '%s_normal.hnv'%app_name)
        self.__factoryNvPath = os.path.join(root_path, 'build', 'build_tmp', 'nv', '%s_factory.hnv'%app_name)
        self.__pktPath = os.path.join(root_path, usr_realtive_output, 'output', 'bin')
        self.__key_dir_path = os.path.join(root_path, 'tools', 'sign_tool')
        self.__lzma_tool_path = os.path.join(root_path, r'tools', r'lzma_tool', r'lzma_tool')
        self.__build_tmp_path = os.path.join(root_path, usr_realtive_output, 'output', 'bin')
        self.__image_id = 0x3C78961E
        self.__kernel_file_ver = kernel_file_ver
        self.__flashboot_file_ver = flashboot_file_ver
        self.__encrypt_flag = 0x42
        self.__sign_alg = sign_alg
        self.__boot_bin_max_size = 32*1024 #32K
        self.__kernel_1st_bin_max_size = 912*1024 #912K
        self.__kernel_2nd_bin_max_size = 968*1024 #968K
        self.__kernel_bin_max_size = self.__kernel_1st_bin_max_size
        self.__kernel_upg_max_size = (912 + 968) * 1024
        self.__factory_bin_max_size = 600*1024 #600K
        self.__chip_product_name = chip_product
        self.__file_attr_encrypt = 0x2 # encrypt 不加密是1，加密是2
        self.__kernel_file_attr_ota = 0x4 # compression ota
        self.__flashboot_file_attr_ota = 0x4 # compression ota
        self.__ota_mode = ota_mode #0：compression ota; 1: dual partition ota

    def set_file_attr_encrypt(self, attr_encrypt):
        self.__file_attr_encrypt = attr_encrypt
        print("---------__file_attr_encrypt = %d-----"%attr_encrypt)

    def set_kernel_file_attr_ota(self, attr_ota):
        if attr_ota == 'A':
            attr_ota = 1
        elif attr_ota == 'B':
            attr_ota = 2
        self.__kernel_file_attr_ota = attr_ota
        print("--set_kernel_file_attr_ota----%s------"%attr_ota)

    def set_flashboot_file_attr_ota(self, attr_ota):
        self.__flashboot_file_attr_ota = attr_ota

    def set_chip_product_name(self, name):
        self.__chip_product_name = name

    def set_kernel_max_size(self, signature):
        if signature == 'A':
            self.__kernel_bin_max_size = self.__kernel_1st_bin_max_size
        elif signature == 'B':
            self.__kernel_bin_max_size = self.__kernel_2nd_bin_max_size
        elif signature == 0:
            self.__kernel_bin_max_size = self.__kernel_upg_max_size
        elif signature == 4:
            self.__kernel_bin_max_size = self.__factory_bin_max_size
        else:
            sys.exit("[ERR]signature err: < %s >, from: %s"%(signature, os.path.realpath(__file__)))
        print("--------------------%s---------"%signature)

    def set_src_path(self, boot_bin_path = None, kernel_bin_path = None, normal_nv_path = None, factory_nv_path = None):
        self.__bootBinPath = boot_bin_path if boot_bin_path is not None else self.__bootBinPath
        self.__kernelBinPath = kernel_bin_path if kernel_bin_path is not None else self.__kernelBinPath
        self.__normalNvPath = normal_nv_path if normal_nv_path is not None else self.__normalNvPath
        self.__factoryNvPath = factory_nv_path if factory_nv_path is not None else self.__factoryNvPath

    def set_pkt_path(self, pkt_dir_path):
        self.__pktPath = pkt_dir_path

    def set_build_temp_path(self, build_temp_path):
        self.__build_tmp_path = build_temp_path

    def set_app_name(self, app_name):
        self.__app_name = app_name

    def set_image_id(self, image_id):
        self.__image_id = image_id

    def set_kernel_file_ver(self, file_version):
        self.__kernel_file_ver = file_version

    def set_flashboot_file_ver(self, file_version):
        self.__flashboot_file_ver = file_version

    def get_kernel_file_ver(self):
        return self.__kernel_file_ver

    def get_flashboot_file_ver(self):
        return self.__flashboot_file_ver

    def set_encrypt_flag(self, encrypt_flag):
        self.__encrypt_flag = encrypt_flag

    def set_sign_alg(self, sign_alg):
        self.__sign_alg = sign_alg

    def BuildUpgBin(self, target = None):
        app_name = self.__app_name
        pkt_dir_path = self.__pktPath
        file_attr = (self.__file_attr_encrypt << 6) + self.__kernel_file_attr_ota

        #升级文件配置
        kernel_file = self.__kernelBinPath
        normal_nv_file = self.__normalNvPath
        if not os.path.exists(normal_nv_file):
            print("normal_nv_file from: ", normal_nv_file)
            sys.exit("[ERR]normal nv file is not exist, from: %s"%os.path.realpath(__file__))

        if not os.path.exists(kernel_file):
            print("kernel_file from: ", kernel_file)
            sys.exit("[ERR]kernel file is not exist, from: %s"%os.path.realpath(__file__))

        # 构造输出文件名 #
        image_file = os.path.join(pkt_dir_path, '%s_ota.bin'%app_name) if target is None else target
        print("kernel_file from: ", kernel_file)
        print("********************package kernel&nv upgrade file********************")
        print("*****************************self.__sign_alg = %d****************************************************"%(self.__sign_alg))
        MAKE_IMAGE.make_hupg(self.__image_id, self.__kernel_file_ver, self.__encrypt_flag, kernel_file, normal_nv_file, image_file, self.__key_dir_path, self.__kernel_bin_max_size, self.__sign_alg, self.__chip_product_name, file_attr)
        return image_file
 
    def BuildUpgBurnBin(self, target = None):
        app_name = self.__app_name
        pkt_dir_path = self.__build_tmp_path
        file_attr = (self.__file_attr_encrypt << 6) + self.__kernel_file_attr_ota
 
        #升级文件配置
        kernel_file = self.__kernelBinPath
        normal_nv_file = self.__normalNvPath
        if not os.path.exists(normal_nv_file):
            print("normal_nv_file from: ", normal_nv_file)
            sys.exit("[ERR]normal nv file is not exist, from: %s"%os.path.realpath(__file__))
 
        if not os.path.exists(kernel_file):
            print("kernel_file from: ", kernel_file)
            sys.exit("[ERR]kernel file is not exist, from: %s"%os.path.realpath(__file__))
 
        # 构造输出文件名 #
        image_file = os.path.join(pkt_dir_path, '%s_ota_unencrypt.bin'%app_name) if target is None else target
        print("********************package kernel&nv upgrade file********************")
        MAKE_IMAGE.make_hupg(self.__image_id, self.__kernel_file_ver, 0x42, kernel_file, normal_nv_file, image_file, self.__key_dir_path, self.__kernel_bin_max_size, self.__sign_alg, self.__chip_product_name, file_attr)
        return image_file

    def BuildHiburnBin(self, burn_bin = None, ota_file = None):
        app_name = self.__app_name
        pkt_dir_path = self.__pktPath
        ota_mode = self.__ota_mode

        #烧写文件配置
        flash_boot_file = self.__bootBinPath
        factory_nv_file = self.__factoryNvPath
        normal_nv_file = self.__normalNvPath
        if ota_mode == 1:
            upg_file = self.BuildUpgBurnBin()
        else:
            upg_file = os.path.join(pkt_dir_path, '%s_%s.%s'%(app_name, 'ota', 'bin')) if ota_file is None else ota_file
            print("------------------------upg_file = %s-----"%(upg_file))
 
        if not os.path.exists(flash_boot_file):
            print("flash_boot_file from: ", flash_boot_file)
            sys.exit("[ERR]flash boot file is not exist, from: %s"%os.path.realpath(__file__))

        if not os.path.exists(factory_nv_file):
            print("factory_nv_file from: ", factory_nv_file)
            sys.exit("[ERR]factory nv file is not exist, from: %s"%os.path.realpath(__file__))

        if not os.path.exists(normal_nv_file):
            print("normal_nv_file from: ", normal_nv_file)
            sys.exit("[ERR]normal nv file is not exist, from: %s"%os.path.realpath(__file__))

        if not os.path.exists(upg_file):
            print("ota file from: ", upg_file)
            sys.exit("[ERR]ota file is not exist, from: %s"%os.path.realpath(__file__))

        # 构造输出文件名 #
        image_file = os.path.join(pkt_dir_path, '%s_burn.bin'%app_name) if burn_bin is None else burn_bin
        print("********************package hiburn file********************")
        MAKE_IMAGE.make_hbin(flash_boot_file, factory_nv_file, normal_nv_file, upg_file, image_file)
        return image_file

    def BuildCompressUpgBin(self, compress_ota_bin = None, ota_file = None):
        app_name = self.__app_name
        pkt_dir_path = self.__pktPath
        file_attr = (self.__file_attr_encrypt << 6) + self.__kernel_file_attr_ota
 
        #制作压缩升级文件依赖文件
        upg_file = os.path.join(pkt_dir_path, '%s_%s.%s'%(app_name, 'ota', 'bin')) if ota_file == None else ota_file
 
        if not os.path.exists(upg_file):
            print("compress ota file from: ", upg_file)
            sys.exit("[ERR]ota file is not exist, from: %s"%os.path.realpath(__file__))
 
        # 构造输出文件名 #
        image_file = os.path.join(pkt_dir_path, '%s_ota.bin'%app_name) if compress_ota_bin == None else compress_ota_bin
        print("********************package compress upgrade file********************")
        MAKE_IMAGE.make_compress_hupg(self.__image_id, self.__kernel_file_ver, self.__encrypt_flag, upg_file, image_file, self.__key_dir_path, self.__kernel_upg_max_size, self.__sign_alg, self.__lzma_tool_path, self.__build_tmp_path, self.__chip_product_name, file_attr)
        return image_file

# main function #

def get_opt_val(options, option):
    bool_list = ['Y', 'y', 'N', 'n']
    if options[option].isdigit():
        return int(options.get(option))
    elif options[option] in bool_list:
        return options[option].lower()
    else:
        return options[option].strip('"')

def scons_get_cfg_val(option):
    usr_config = usr_cfg_main()
    sys_config = sys_cfg_main()
    if option in usr_config.keys():
        return get_opt_val(usr_config, option)
    elif option in sys_config.keys():
        return get_opt_val(sys_config, option)
    else:
        return 'n'

class crc16:
    POLYNOMIAL = 0x1021
    PRESET = 0x0000
    _tab = []
    def __init__(self):
        self._tab = [self._initial(i) for i in range(256)]

    def _initial(self, c):
        crc = 0
        c = c << 8
        for j in range(8):
            if (crc ^ c) & 0x8000:
                crc = (crc << 1) ^ self.POLYNOMIAL
            else:
                crc = crc << 1
            c = c << 1
        return crc

    def _update_crc(self, crc, c):
        cc = 0xff & int(c)

        tmp = (crc >> 8) ^ cc
        crc = (crc << 8) ^ self._tab[tmp & 0xff]
        crc = crc & 0xffff

        return crc

    def crc(self, str):
        crc = self.PRESET
        for c in str:
            crc = self._update_crc(crc, ord(c))
        return crc

    def crcb(self, i):
        crc = self.PRESET
        for c in i:
            crc = self._update_crc(crc, c)
        return crc

t = crc16()
def packet_bin(outputPath, inputList):
    pathList = []
    burnAddrList = []
    burnSizeList = []
    imageSizeList = []
    typeList = []
    for item in inputList:
        path, burnAddr, burnSize, type = item.split("|")
        imageSize = os.path.getsize(path)
        pathList.append(path)
        burnAddrList.append(int(burnAddr))
        burnSizeList.append(int(burnSize))
        imageSizeList.append(imageSize)
        typeList.append(int(type))

    print(pathList)
    print(burnAddrList)
    print(burnSizeList)
    print(imageSizeList)
    print(typeList)

    flag = 0xefbeaddf
    print(flag)
    crc = 0
    imageNum = len(pathList)
    headLen = imageNum*52 + 12
    totalFileSize = sum(imageSizeList) + headLen

    with open(outputPath, 'wb+') as file:
        file.write(struct.pack('IHHI', flag, crc, imageNum, totalFileSize))
        startIndex = headLen
        times = 0
        for path in pathList:
            pathName = os.path.basename(path)
            file.write(
                struct.pack('32sIIIII', bytes(pathName, 'ascii'), startIndex, imageSizeList[times], burnAddrList[times],
                            burnSizeList[times], typeList[times]))
            startIndex = startIndex + imageSizeList[times] + 16
            times += 1

        for path in pathList:
            with  open(path, 'rb+') as subfile:
                data = subfile.read()
                file.write(data)
                file.write(struct.pack('IIII', 0, 0, 0, 0))

        file.flush()
        file.seek(6)
        newdata = file.read(headLen - 6)
        crc16 = t.crcb(newdata)
        file.seek(4)
        file.write(struct.pack('H', crc16))

if __name__ == '__main__':
    args = len(sys.argv)
    list = ['burn_bin', 'factory_bin']
    print("----------------------main: args %d-----------------------"%args)
    if args >= 6 and sys.argv[1] in list:
        type = sys.argv[1]
        app_name = sys.argv[2]
        sign_alg = int(sys.argv[3], 16)
        kernel_file_ver = int(sys.argv[4])
        flashboot_file_ver = int(sys.argv[5])
        target = sys.argv[6]
        flash_encrypt_flag = int(sys.argv[8]) 
        target_tmp = os.path.join(root_path, 'build', 'build_tmp', 'cache', '%s_ota_temp.bin'%app_name)

        ota_flag = 1 if scons_get_cfg_val('CONFIG_COMPRESSION_OTA_SUPPORT') != 'y' else 0 
        chip_product = 'Hi3861' if scons_get_cfg_val('CONFIG_TARGET_CHIP_HI3861') == 'y' else 'Hi3861L'
        fu = ImageBuild(app_name, sign_alg, kernel_file_ver, flashboot_file_ver, chip_product, usr_realtive_output='', ota_mode=ota_flag)
        fu.set_pkt_path(os.path.join(root_path, 'output', 'bin'))
        bootBinPath = os.path.join(root_path, 'output', 'bin', '%s_boot_signed.bin'%chip_product)
        fu.set_src_path(bootBinPath)
        fu.set_file_attr_encrypt(flash_encrypt_flag)
        fu.set_flashboot_file_attr_ota(0x3) if scons_get_cfg_val('CONFIG_COMPRESSION_OTA_SUPPORT') != 'y' else None 
        fu.set_encrypt_flag(0x42) 

        version_bin = bytearray(8)
        boot_ver_bytes = flashboot_file_ver.to_bytes(4, byteorder = 'little', signed = True)
        kernel_ver_bytes = kernel_file_ver.to_bytes(4, byteorder = 'little', signed = True)
        version_bin[0:4] = boot_ver_bytes
        version_bin[4:8] = kernel_ver_bytes
        version_file = os.path.join(os.path.dirname(target), '%s_vercfg.bin'%app_name)

        if type == 'burn_bin':
            print('burn_bin')
            kernelBinPath = sys.argv[7]
            fu.set_src_path(kernel_bin_path = kernelBinPath)
            fu.set_kernel_max_size(0)
            if (scons_get_cfg_val('CONFIG_COMPRESSION_OTA_SUPPORT') != 'y') and (flash_encrypt_flag == 2):
                fu.set_encrypt_flag(0xFF)
            fu.BuildUpgBin(target_tmp)

            ota_bin = target_tmp
            fu.set_src_path(kernel_bin_path = target_tmp) if scons_get_cfg_val('CONFIG_COMPRESSION_OTA_SUPPORT') != 'y' else None
            fu.set_build_temp_path(build_temp_path = os.path.join(root_path, 'build', 'build_tmp', 'cache'))
            fu.BuildHiburnBin(target, ota_bin)
            with open(version_file, 'wb+') as fp:
                fp.write(version_bin)

            hilink_enable = False
            if (scons_get_cfg_val('CONFIG_HILINK') == 'y'):
                hilink_enable = True

            burn_for_erase_bin = os.path.join(root_path, 'build', 'basebin', 'burn_for_erase_4k.bin')
            allinone = os.path.join(os.path.dirname(target), '%s_allinone.bin'%app_name)
            loader_bin = os.path.join(os.path.dirname(target), '%s_loader_signed.bin'%chip_product)
            efuse_bin = os.path.join(root_path, 'build', 'basebin', 'efuse_cfg.bin')
            efuse_bin = None if not os.path.exists(efuse_bin) else efuse_bin
            boot_b = os.path.join(os.path.dirname(target), "%s_boot_signed_B.bin"%(chip_product))
            boot_b_size = os.path.getsize(boot_b)
            factory_bin_path = os.path.join(root_path, 'build', 'libs', 'factory_bin')
            factory_bin = os.path.join(factory_bin_path, '%s_factory.bin'%app_name)
            #证书安全存储示例
            tee_cert1_file = os.path.join(root_path, 'build', 'basebin', 'tee_cert1.bin');
            tee_cert2_file = os.path.join(root_path, 'build', 'basebin', 'tee_cert2.bin');
            tee_key_file = os.path.join(root_path, 'build', 'basebin', 'tee_key.bin');
            tee_cert_key_bin_max = 12*1024; #必须为4KB证书倍，需匹配分区表确定烧写地址和大小
            tee_total_file_cnt = 3; #3个文件：2个证书，1个key。
            burn_tee_cert = False
            if ((os.path.exists(tee_cert1_file)) and (os.path.exists(tee_cert2_file)) and (os.path.exists(tee_key_file))):
                burn_tee_cert = True

            burn_bin_ease_size = 0x200000;
            if (hilink_enable == True):
                burn_bin_ease_size = 0x200000 - 0x8000 - 0x1000 - 0x2000
            if (burn_tee_cert == True):
                burn_bin_ease_size = 0x200000 - 0x8000 - 0x1000 - 0x2000 - 0x5000

            if os.path.exists(factory_bin):
                list = ['%s|0|0|0'%loader_bin, '%s|0|0|3'%efuse_bin, '%s|0|%d|1'%(target, burn_bin_ease_size), '%s|%d|%d|6'%(factory_bin, 0x14D000, 0x96000)] if efuse_bin!=None else ['%s|0|0|0'%loader_bin, '%s|0|%d|1'%(target, burn_bin_ease_size), '%s|%d|%d|6'%(factory_bin, 0x14D000, 0x96000)]
                shutil.copytree(factory_bin_path, os.path.join(os.path.dirname(target), 'factory_bin'))
            else:
                list = ['%s|0|0|0'%loader_bin, '%s|0|0|3'%efuse_bin, '%s|0|%d|1'%(target, burn_bin_ease_size)] if efuse_bin!=None else ['%s|0|0|0'%loader_bin, '%s|0|%d|1'%(target, burn_bin_ease_size)]

            if ((hilink_enable == True) or (burn_tee_cert == True)):
                list.append('%s|%d|%d|1'%(burn_for_erase_bin, 0x200000 - 0x8000 - 0x1000, 0x1000))

            list.append('%s|%d|%d|1'%(boot_b, 0x200000 - boot_b_size, boot_b_size));

            if (burn_tee_cert == True):
                cert_key_bin = bytearray(tee_cert_key_bin_max)
                tee_cert1_size = os.path.getsize(tee_cert1_file)
                tee_cert2_size = os.path.getsize(tee_cert2_file)
                tee_key_size = os.path.getsize(tee_key_file)
                total_cert_key_size = tee_cert1_size + tee_cert2_size + tee_key_size
                if (total_cert_key_size > tee_cert_key_bin_max - 4 - 4 - 4*tee_total_file_cnt):
                    print('[ERROR]: cert total len bigger than tee_cert_key_bin_max!!!')
                    sys.exit(1)
                else:
                    with open(tee_cert1_file, 'rb') as fp:
                        tee_cert1_bin = fp.read()
                    with open(tee_cert2_file, 'rb') as fp:
                        tee_cert2_bin = fp.read()
                    with open(tee_key_file, 'rb') as fp:
                        tee_key_bin = fp.read()

                    #填充头部结构
                    start_flag = 0xDEADBEEF
                    start_flag_bytes = start_flag.to_bytes(4, byteorder = 'little', signed = False)
                    cert_key_bin[0:4] = start_flag_bytes #填充魔术字
                    tee_total_file_cnt_bytes = tee_total_file_cnt.to_bytes(4, byteorder = 'little', signed = True)
                    cert_key_bin[4:8] = tee_total_file_cnt_bytes #填充总的文件数
                    #填充各文件的大小
                    cert_key_bin[8:12] = tee_cert1_size.to_bytes(4, byteorder = 'little', signed = True)
                    cert_key_bin[12:16] = tee_cert2_size.to_bytes(4, byteorder = 'little', signed = True)
                    cert_key_bin[16:20] = tee_key_size.to_bytes(4, byteorder = 'little', signed = True)
                    #填充各文件
                    cert_key_bin[20:20 + tee_cert1_size] = tee_cert1_bin
                    cert_key_bin[20 + tee_cert1_size:20 + tee_cert1_size + tee_cert2_size] = tee_cert2_bin
                    cert_key_bin[20 + tee_cert1_size + tee_cert2_size:20 + tee_cert1_size + tee_cert2_size + tee_key_size] = tee_key_bin
                    #写文件
                    cert_bin_file = os.path.join(root_path, "output", "bin", '%s_tee_cert_key.bin'%app_name)
                    with open(cert_bin_file, 'wb+') as fp:
                        fp.write(cert_key_bin)
                    list.append('%s|%d|%d|1'%(cert_bin_file, 0x200000 - 0x8000 - 0x1000 - 0x2000 - 0x5000, tee_cert_key_bin_max))

            if (sign_alg != 0x3F): #only need write ver file in secure boot mode.
                list.append('%s|0|0|7'%version_file)
            packet_bin(allinone, list)
            #if os.path.exists(factory_bin_path):
                #shutil.rmtree(factory_bin_path)

            target_ota_compress = os.path.join(root_path, "output", "bin", '%s_ota.bin'%app_name)
            ota_bin = target_tmp
            fu.set_kernel_file_attr_ota(0x4)
            fu.set_kernel_max_size(0) #(912+968)KB
            fu.set_build_temp_path(build_temp_path = os.path.dirname(ota_bin))
            if flash_encrypt_flag == 2:
                fu.set_encrypt_flag(0xFF)
            fu.BuildCompressUpgBin(target_ota_compress, ota_bin)
        elif type == 'factory_bin':
            print('factory_bin')
            kernelBinPath = sys.argv[7]
            fu.set_src_path(kernel_bin_path = kernelBinPath)
            fu.set_kernel_max_size(0x4)
            fu.set_kernel_file_attr_ota('A')
            fu.BuildUpgBin(target)
    else:
        print('[ERROR]: build ota parameters err!!!')
        sys.exit(1)
