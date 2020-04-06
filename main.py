from packer import Packer
from unpacker import Unpacker

unp = Unpacker('/mnt/d/mobile/firm/T91_4_TF/T91_4.bin')
unp.export('/mnt/d/mobile/unpack', unpack_files = True, crc_check = True)
print(unp)

p = Packer('/mnt/d/mobile/test_firm')
p.export('/mnt/d/mobile/T91_4.bin.new')