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
