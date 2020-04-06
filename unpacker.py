from Crypto.Cipher import DES
import struct
import zlib
import json
import os
from util import *

class Unpacker:
    def __init__(self, fw_path, des_key = '0123456789ABCDEF'.decode('hex'), fw_name='T91_4.bin'):
        self.des_key = des_key
        self.fw_f = open(fw_path, 'rb')
        self.header = DES.new(self.des_key, DES.MODE_ECB).decrypt(self.fw_f.read(0x100000))
        if fw_name is None: fw_name = os.path.basename(fw_path)
        self.fw_name = fw_name
        self.load()

    def load(self):
        header = self.header
        self.bin_num = strange_bytes_to_int(header[1608:1608+4])
        self.cfg_cnt = strange_bytes_to_int(header[1088:1088+4])
        self.bin_cnt = strange_bytes_to_int(header[1092:1092+4])
        if self.bin_num == 1:
                self.phone_version = get_c_str(header, 64)
                self.packer_version = get_c_str(header, 0)
                self.img_version = get_c_str(header, 576)
        else:
            raise Exception("error:bin num %d don't support\n", bin_num)


    def export(self, path, unpack_files=True, crc_check = True):
        pos = 0x2800
        header = self.header
        fw_f = self.fw_f
        cfg_order = []
        bin_order = []
        for i in range(self.cfg_cnt + self.bin_cnt):
            bin_name = get_c_str(header, pos)
            f_name = get_c_str(header, pos+64)
            size = struct.unpack('<I', header[pos+136:pos+136+4])[0]
            crc32 = struct.unpack('<i', header[pos+144:pos+144+4])[0]
            offset = struct.unpack('<Q', header[pos+128:pos+128+8])[0]*512
            r_size = (size+7)&0xFFFFFFF8
            r_crc32 = 0
            if i < self.cfg_cnt:
                cfg_order += [f_name]
            else:
                bin_order += [f_name]

            if unpack_files:
                fw_f.seek(offset)
                f_data = fw_f.read(r_size)
                if i < self.cfg_cnt:
                    f_data = DES.new(self.des_key, DES.MODE_ECB).decrypt(f_data)[:size]
                else:
                    f_data = f_data[:size]
                if crc_check:
                    r_crc32 = zlib.crc32(f_data)

            print 'bin name:', bin_name, 'file name:', f_name, 'size:', size, 'crc32', crc32, 'real crc32:', r_crc32, 'offset', offset

            if crc_check and (r_crc32 != crc32):
                raise Exception('CRC32 mismatch')
            if unpack_files:
                fl = open(os.path.join(path, f_name), 'wb')
                fl.write(f_data)
                fl.close()

            pos += 0xa0
        fw_info = {'fw_name': self.fw_name, 'bin_num': self.bin_num, 'phone_version': self.phone_version, 'cfg_cnt': self.cfg_cnt, 'cfg_order': cfg_order, 'bin_cnt': self.bin_cnt, 'bin_order': bin_order, 'packer_version': self.packer_version, 'img_version': self.img_version}
        assert(self.bin_cnt == len(bin_order))
        assert(self.cfg_cnt == len(cfg_order))
        f = open(os.path.join(path, INFO_FILE_NAME), 'w')
        f.write(json.dumps(fw_info))
        f.close()

    def __repr__(self):
        res = ''
        res += 'Firmware Info:'
        res += '\nPhone version: %s' % self.phone_version
        res += '\nBinary num: %d' % self.bin_num
        res += '\nConfig count: %d' % self.cfg_cnt
        res += '\nBinary count: %d' % self.bin_cnt
        res += '\nPacker version: %s' % self.packer_version
        res += '\nImage version: %s' % self.img_version
        return res