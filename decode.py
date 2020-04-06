from Crypto.Cipher import DES
import struct
import zlib
import binascii
import json
import os

#TODO: exceptions

def get_c_str(data, s=0):
    data = data[s:]
    return data[:data.find('\x00')]

def write_c_str(data, pos, s):
    return str(data[:pos])+str(s)+str(data[pos+len(s):])

def int_to_strange_bytes(d):
    res = ''
    res += chr(d & 0xFF)
    d = (d-d & 0xFF) >> 4
    res += chr(d & 0xFF)
    d = (d-d & 0xFF) >> 4
    res += chr(d & 0xFF)
    d = (d-d & 0xFF) >> 4
    res += chr(d & 0xFF)
    d = (d-d & 0xFF) >> 4
    assert(d==0)
    return res

def strange_bytes_to_int(bts):
    return ord(bts[0]) | (ord(bts[1]) << 4) | (ord(bts[2]) << 8) | (ord(bts[3]) << 12)

INFO_FILE_NAME = 'fw_unpack_info.json'

class Unpacker:
    def __init__(self, fw_path, des_key = '0123456789ABCDEF'.decode('hex'), fw_name='T91_4.bin'):
        self.des_key = des_key
        self.fw_f = open(fw_path, 'rb')
        self.header = DES.new(self.des_key, DES.MODE_ECB).decrypt(self.fw_f.read(0x100000))
        f = open('/mnt/d/mobile/head', 'wb')
        f.write(self.header)
        f.close()
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

        ##unknown data to match source firmware
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

# unp = Unpacker('/mnt/d/mobile/firm/T91_4_TF/T91_4.bin')
# unp.export('/mnt/d/mobile/unpack', unpack_files = False, crc_check = False)
# print(unp)

p = Packer('/mnt/d/mobile/test_firm')
p.export('/mnt/d/mobile/T91_4.bin.new')