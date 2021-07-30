import pykd

def get_function_address(function_name):
    res = pykd.dbgCommand("x " + function_name)
    if res.count("\n") > 1:
        print("Warning, more than one result for" + function_name)
    return res.split()[0]

class Reversing(pykd.eventHandler):
    def __init__(self,function_to_trace):
        self.function_addr = get_function_address(function_to_trace)
        if self.function_addr == None: return
        print(f"[+] Address of {function_to_trace} -> {self.function_addr}")
        print(int(self.function_addr,16))
        self.bp_init = pykd.setBp(int(self.function_addr,16),self.handle_bp)
        self.bp_on_buffer = None
        self.bp_end = None
    
    def handle_bp(self):
        print("Recv Called")
        if self.bp_end == None:
            disAsm = pykd.dbgCommand("uf WSOCK32!recv").split("\n")
            esp_buffer = pykd.dbgCommand("dds esp L5").split("\n")[2].split("  ")[1]
            esp_buffer_len = pykd.dbgCommand("dds esp L5").split("\n")[3].split("  ")[1]
            print("buffer len->",esp_buffer_len)
            print("buffer address",esp_buffer)
            print("Executing -> ba r{} {}".format("1",hex(int(esp_buffer,16))))
            #pykd.dbgCommand("ba r4 {}".format(hex(int(esp_buffer,16))))
            self.bp_on_buffer = pykd.setBp(int(esp_buffer,16),0x1,0x1,self.on_access)
            print("brrrr")
            for i in disAsm:
                if "ret" in i:
                    self.ret_addr = i.split()[0]
                    break
            self.bp_end = pykd.setBp(int(self.ret_addr,16),self.return_call_back)
        return False
    
    def return_call_back(self):
        print("Recv Returned!")
        return False

    def on_access(self):
        print("Buffer For WriteFile Accessed!")
        addr =  pykd.dbgCommand("k").split("\n")[1].split(" ")[2]
        print(addr)
        return False

    
Reversing("WSOCK32!recv")
pykd.go()
