var g_dexmap = new Map();

function dump_dex(){
    Module.enumerateSymbolsSync("libart.so").forEach(symbol => {
       if(symbol.name.indexOf("LoadMethod") >= 0 &&
            symbol.name.indexOf("Check") < 0){
            console.log("[*] find LoadMethod =>[" + symbol.name +": " + symbol.address + "]");
            
            Interceptor.attach(symbol.address, {
                onEnter: function(args){
                    this.dexfile = args[1];
                },
                onLeave: function(ret){
                    var begin = ptr(this.dexfile.add(Process.pointerSize)).readPointer();
                    var size = ptr(this.dexfile.add(Process.pointerSize*2)).readPointer();

                    if(g_dexmap[size] == undefined){
                        g_dexmap[size] = begin;
                        console.log("[+] find dex => begin=" + begin + ", size=" + size);
                        //console.log(hexdump(begin, size));
                    }
                }
            });
       } 
    });
}

function dump(){
    for(var size in g_dexmap){
        // console.log(ptr(g_dexmap[size]).readByteArray(Number(size)));
        // console.log(typeof(Number(size)));
        
        var filepath = "/sdcard/Download/" + size + ".dex";
        console.log("[+] dump dex => " + filepath);
        var dexfile = new File(filepath, "w");
        dexfile.write(ptr(g_dexmap[size]).readByteArray(Number(size)));
        dexfile.close();
    }
}

setImmediate(dump_dex);