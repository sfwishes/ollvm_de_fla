

def formatAddrToMyFormat(addr):
    tmp = addr
    tmp.upper()
    if '0X' in tmp:
        tmp = tmp[2:]
    return tmp

def isSameAddress(addr1, addr2):
    tmp1 = formatAddrToMyFormat(addr1)
    tmp2 = formatAddrToMyFormat(addr2)

    if tmp1 == tmp2:
        return True

    return False