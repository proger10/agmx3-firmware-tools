from Crypto.Cipher import DES
import struct
import zlib
import json
import os
from util import *

class Packer:
    def __init__(self, path, des_key = '0123456789ABCDEF'.decode('hex')):
        self.des_key = des_key
        self.path = path
        self.load_info()

    def load_info(self):
        f = open(os.path.join(self.path, INFO_FILE_NAME), 'r')
        fw_info = json.loads(f.read())
        f.close()
        self.bin_num = fw_info['bin_num'];
        self.phone_version = fw_info['phone_version']
        if 'cfg_cnt' in fw_info:
            self.cfg_cnt = fw_info['cfg_cnt']
            self.cfg_order = fw_info['cfg_order']
        if 'bin_cnt' in fw_info:
            self.bin_cnt = fw_info['bin_cnt']
            self.bin_order = fw_info['bin_order']
        self.packer_version = fw_info['packer_version']
        self.img_version = fw_info['img_version']
        self.fw_name = fw_info['fw_name']

    def make_header(self):
        header = '\x00'*0x100000

        header = write_c_str(header, 1608, int_to_strange_bytes(self.bin_num))
        header = write_c_str(header, 1088, int_to_strange_bytes(self.cfg_cnt))
        header = write_c_str(header, 1092, int_to_strange_bytes(self.bin_cnt))
        header = write_c_str(header, 64, self.phone_version)
        header = write_c_str(header, 0, self.packer_version)
        header = write_c_str(header, 576, self.img_version)

        ## unknown data to match source firmware
        ## TODO
        header = write_c_str(header, 0x448, 'Hisense')
        header = write_c_str(header, 0x64c, '7E91E502'.decode('hex'))

        pos = 0x2800
        offset = 2048*512
        for f_name in self.cfg_order+self.bin_order:
            f = open(os.path.join(self.path, f_name), 'rb')
            f_data = f.read()
            f.close()

            size = len(f_data)
            crc32 = zlib.crc32(f_data)

            f_data += '\x00'*((512-(len(f_data) % 512)) % 512)
            if f_name in self.cfg_order:
                f_data = DES.new(self.des_key, DES.MODE_ECB).encrypt(f_data)

            header = write_c_str(header, pos, self.fw_name)
            header = write_c_str(header, pos + 64, f_name)
            header = write_c_str(header, pos + 136, struct.pack('<I', size))
            header = write_c_str(header, pos + 144, struct.pack('<i', crc32))
            header = write_c_str(header, pos + 128, struct.pack('<Q', offset/512))
            self.fw_f.seek(offset)
            self.fw_f.write(f_data)
            offset += size
            if offset % 512 != 0: offset += 512-(offset % 512)
            pos += 0xa0


        return header

    def export(self, fname):
        self.fw_f = open(fname, 'wb')
        header = self.make_header()
        f = open('/mnt/d/mobile/head.test', 'wb')
        f.write(header)
        f.close()

        self.fw_f.seek(0)
        self.fw_f.write(DES.new(self.des_key, DES.MODE_ECB).encrypt(header))
        self.fw_f.close()