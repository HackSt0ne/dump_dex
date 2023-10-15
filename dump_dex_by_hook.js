var g_dex_map = new Map();

function get_self_process_name() {
    var openPtr = Module.getExportByName('libc.so', 'open');
    var open = new NativeFunction(openPtr, 'int', ['pointer', 'int']);

    var readPtr = Module.getExportByName("libc.so", "read");
    var read = new NativeFunction(readPtr, "int", ["int", "pointer", "int"]);

    var closePtr = Module.getExportByName('libc.so', 'close');
    var close = new NativeFunction(closePtr, 'int', ['int']);

    var path = Memory.allocUtf8String("/proc/self/cmdline");
    var fd = open(path, 0);
    if (fd != -1) {
        var buffer = Memory.alloc(0x1000);

        var result = read(fd, buffer, 0x1000);
        close(fd);
        result = ptr(buffer).readCString();
        return result;
    }

    return "-1";
}

function chmod(path) {
    var chmodPtr = Module.getExportByName('libc.so', 'chmod');
    var chmod = new NativeFunction(chmodPtr, 'int', ['pointer', 'int']);
    var cPath = Memory.allocUtf8String(path);
    chmod(cPath, 755);
}

function mkdir(path) {
    var mkdirPtr = Module.getExportByName('libc.so', 'mkdir');
    var mkdir = new NativeFunction(mkdirPtr, 'int', ['pointer', 'int']);

    var opendirPtr = Module.getExportByName('libc.so', 'opendir');
    var opendir = new NativeFunction(opendirPtr, 'pointer', ['pointer']);

    var closedirPtr = Module.getExportByName('libc.so', 'closedir');
    var closedir = new NativeFunction(closedirPtr, 'int', ['pointer']);

    var cPath = Memory.allocUtf8String(path);
    var dir = opendir(cPath);
    if (dir != 0) {
        closedir(dir);
        return 0;
    }
    mkdir(cPath, 755);
    chmod(path);
}

function dump(){
    for(var dex_size in g_dex_map){
        var process_name = get_self_process_name();
        var dex_dir_path = "/data/data/" + process_name + "/dump_dex";
        mkdir(dex_dir_path);
        var dex_path = dex_dir_path + "/" + dex_size + ".dex";
        console.log("[+] dump dex: " + dex_path);
        var dexfile = new File(dex_path, "w");
        dexfile.write(ptr(g_dex_map[dex_size]).readByteArray(Number(dex_size)));
        dexfile.close();
    }
}

function hook(){
    //LoadClassMembers
    var libart = Process.findModuleByName("libart.so");
    if(libart == null){
        console.log("not fount libart.so");
        return;
    }

    libart.enumerateSymbols().forEach((symbol) =>{
        if(symbol.name.indexOf("LoadClassMembers") >= 0 &&
            symbol.name.indexOf("Check") <= 0){
                console.log("\nfound LoadClassMembers addr: " + symbol.address);
                Interceptor.attach(symbol.address, {
                    onEnter(args){
                        var dex_file = args[2];
                        var dex_begin = ptr(dex_file.add(Process.pointerSize)).readPointer();
                        var dex_size = ptr(dex_file.add(Process.pointerSize*2)).readU32();

                        if(g_dex_map[dex_size] == undefined){
                            //new dex
                            console.log("[+] found dex, begin=" + dex_begin + ", size=" + dex_size);
                            //onsole.log(hexdump(dex_begin), {length: 16});
                            g_dex_map[dex_size] = dex_begin;
                        }
                    }
                });
            }
    });
}


function main(){
    hook()
}

// after app start, execute dump()
setImmediate(main);