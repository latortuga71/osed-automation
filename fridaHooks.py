from __future__ import print_function
import frida
import sys
import os

pid = 5264
session = frida.attach(6832)

def on_message(message,data):
    print("[{}] => {}".format(message,data))

script = session.create_script("""
    var version = "Frida Version "+Frida.version +" Loaded";
    send(version);
    Interceptor.attach(Module.findExportByName(null,"recv"),{
        onEnter(args){
            console.log("::: Entering RECV... :::");
            //send("Thread Id: " + this.threadId);
            //send("Return address: " + this.returnAddress);
            //send("Depth: " + this.depth);
            // save arguments /// 
            this.socketFd = args[0].toInt32();
            this.buffer = args[1];
            this.bufferLen = args[2].toInt32();
            console.log("RECV called from : \\n" + Thread.backtrace(this.context,Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\\n"));
        },
        onLeave(retval){
            send("bytes at buffer -> " + this.buffer.readUtf8String().slice(0,5))
            send("Socket File Descriptor : " + this.socketFd);
            send("Buffer Location : " + this.buffer);
            send("Buffer Length : " + this.bufferLen);
            send("RETURN VALUE -> Bytes Read Into Buffer " + retval.toInt32());
            console.log("::: Exiting RECV... :::");
        }
    });
""")
### SETUP OTHER HOOKS ON COMMON UNSAFE FUNCTIONS ### ?

script.on('message',on_message)
script.load()
print("CTRL+Z to detach")
sys.stdin.read()
session.detach()
