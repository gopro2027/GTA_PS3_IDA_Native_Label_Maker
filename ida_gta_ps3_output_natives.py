import idautils
import idaapi
import ctypes
def read_ptr(ea):
  if idaapi.get_inf_structure().is_64bit():
    return idaapi.get_qword(ea)
  return idaapi.get_dword(ea)

def twos_comp(val, bits):
    """compute the 2's complement of int value val"""
    if (val & (1 << (bits - 1))) != 0: # if sign bit is set e.g., 8bit: 128-255
        val = val - (1 << bits)        # compute negative value
    return val                         # return positive value as is

def read_address_from_bl(bl_address):
    return 0

def find_bl(func_address):
    for i in range(8,1000,4):
        addr = func_address + i
        full_instruction = idaapi.get_dword(addr)
        if full_instruction == 0x4E800020:
            return -1

        #example:
        # at 0x14D7180 it's bl sub_3BA5A4 and the value is 0x4AEE3425  dest-src: (0x3BA5A4-0x14D7180) (001110111010010110100100-0001010011010111000110000000) = -01000100011100101111011100 = -0x111CBDC  bits: 010010 10111011100011010000100101 = 0x2EE3424 twos compliment: 0x111CBDC
        # 0x8116A8 it's bl sub_E522BC val: 0x48640C15  dest-src: (0xE522BC-0x8116A8) = 0x640C14                                                                                                           bits: 010010 00011001000000110000010101 = 0x640C15

        # 00000011111111111111111111111110 = 3FFFFFE
        # 11111100000000000000000000000000 = FC000000
        # 01001000000000000000000000000000 = 48000000

        dif = full_instruction & 0x3FFFFFE
        inst = full_instruction & 0xFC000000

        if inst == 0x48000000:
            #bl instruction
            return addr + twos_comp(dif,26)
    return -1



        


def find_vals(value):
    fa = False
    fb = False
    fc = False
    fd = False
    r3_a = 0
    r3_b = 0
    r4_a = 0
    r4_b = 0
    #idaapi.get_dword
    for i in range(4,32,4):
        addr = value - i
        inst = idaapi.get_word(addr)
        val = idaapi.get_word(addr+2)

        if fa == False and inst == 0x3084: #addic     r4, r4
            r4_b = ctypes.c_short(val).value #twos_comp(val,16)
            fa = True
        if fb == False and inst == 0x6063: #ori       r3, r3
            r3_b = val
            fb = True
        if fc == False and inst == 0x3C80: #lis       r4
            r4_a = val
            fc = True
        if fd == False and inst == 0x3C60: #lis       r3,
            r3_a = val
            fd = True

        INSTRUCTIONBYTE = idaapi.get_byte(addr)

        #this could technically be used instead of getting it directly through memory but the logic wouldnt change much anyways
        #inst = idautils.DecodeInstruction(addr+0)
        #print(str(inst.itype)+" "+str(inst.Op1.reg)+" "+hex(inst.Op2.value)+" "+hex(inst.insnpref))

        if INSTRUCTIONBYTE == 0x48: #bl
            break
        if fa == True and fb == True and fc == True and fd == True:
            break
    if fa == True and fb == True and fc == True and fd == True:
        return r3_a << 16 | r3_b, ((r4_a << 16) + (r4_b))
    return 0,0

           
    


#enter in the address of your addNative function here. Examples:
# 1.27: 0x9B7A50
# 1.12: 0x97C3C8 and 0x97C290
funcs = [0x97C3C8,0x97C290]
for func_addr in funcs:
    gen_xrefs = XrefsTo(func_addr, 0)
    for ref in gen_xrefs:
        #prev = Dword(ref.frm - 0x4)
        #prev = read_ptr(ref.frm - 0x4) # this works to read the value
        #prev = idaapi.get_reg_val('r3', ref)
        r3, r4 = find_vals(ref.frm)
        opd_struct = r4
        native_hash = r3
        native_func_address = idaapi.get_dword(opd_struct)
        direct_address = find_bl(native_func_address)
        toc = idaapi.get_dword(opd_struct+4)
        print(hex(native_hash)+","+hex(opd_struct)+","+hex(native_func_address)+","+hex(direct_address)) #+", xref: "+hex(ref.frm)