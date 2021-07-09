function print_output(output)
{
    for (line of output)
    {
        host.diagnostics.debugLog(line, "\n");
    }
}

function open_dev()
{
    var ctl = host.namespace.Debugger.Utility.Control;   
    var output = ctl.ExecuteCommand("!devobj wdnisdrv");
    var devobj = output[0].match(/\(([a-f0-9]+)\)/)[1];
    var devobj_addr = host.parseInt64(devobj, 16);
    host.diagnostics.debugLog("Device object @ ", devobj_addr, "\n");
    // modify the _DEVICE_OBJECT.flags
    // remove DO_EXCLUSIVE
    var flags_addr = devobj_addr.add(0x30);
    // here I can retrieve flags as a number
    var flags = host.memory.readMemoryValues(flags_addr, 1, 2);
    host.diagnostics.debugLog(flags, "\n");
    flags &= 0xFFF7;
    ctl.ExecuteCommand("ew " + flags_addr.toString() + " 0n" + flags);
    host.diagnostics.debugLog("Removed DO_EXCLUSIVE from _DEVICE_OBJECT.flag\n");
    // modify the _SECURITY_DESCRIPTOR.Control
    var sd_addr = host.memory.readMemoryValues(devobj_addr.add(0x110), 1, 8);
    sd_addr = host.parseInt64(sd_addr.toString(), 16);
    host.diagnostics.debugLog("Security descriptor @ ", sd_addr, "\n");
    print_output(ctl.ExecuteCommand("!sd " + sd_addr.toString()));
    var sd_ctrl_addr = sd_addr.add(2);
    ctl.ExecuteCommand("ew " + sd_addr.add(2).toString() + " 8000");
    host.diagnostics.debugLog("Patched security descriptor\n\n");
    print_output(ctl.ExecuteCommand("!sd " + sd_addr.toString()));
}