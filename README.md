# Windefender Network Inspection tools

Along with the publication of a blogpost regarding Windefender network inspection's driver, a small utility called WindTalker is released.
This tool allows to:

* inject network packets inside an existing connection
* watch live connection notifications from the network inspection driver
* BSOD one's machine
* ...

This tool was tested against the version *4.18.2102.3-0* of `WdNisDrv.sys`.
With a little bit of reverse engineering and some minor changes, the utility can be updated.

For more information regarding the research, please refer to the blogpost.

# Testing the utility

In order to test it, one needs to have a live kernel debugging session with WinDbg Preview.
First, one needs to *break* and run the js script `mod_sec.js` to remove the security on the device object of the driver:

```
dx Debugger.State.Scripts.mod_sec.Contents.open_dev()
```

Once the execution of the script is finished, one MUST make sure that the network protection is set to 1 (ENABLED).
Also, since the device object was meant to be opened exclusively by one process (WdNisSvc), one WILL need to reactivate the network protection between 2 runs.
One can achieve that by opening a cmd prompt as an administrator and issuing the following command (inside the target machine):

```
Set-MpPreference -EnableNetworkProtection 1
```

One can alternate between 0 and 1 to make sure the filtering mecanism is still in place on the system and the utility can interact with the device.

The tool can be launched with some options:

- inject : injects a packet from a file inside an open connection
- notify : displays live connection notifications
- bsod : triggers the integer overflow via the IP address exclusion bug
- ipexclu : randomly generates an IPv4 address to exclude (testing purposes only)

For instance, with the `notify` command, one can open any installed internet browser and should see a long list of notifications.

When testing packet injection inside a connection, one will need to retrieve its *flow handle* and the filter engine callout id.
The second one can be retrieved via the XML file or just like the first one via the notify command of the utility.

For instance, let's take the scenario where a debuggee machine A wants to request an HTTP server B.
After having setup the notify commands, A can start querying B.
The flow handle can be retrieved inside the flow established connection notification.
One should leave the notify command running and open another termininal and use the inject command with the retrieved parameters.


# Compiling WindTalker

Visual Studio needs to be installed. It was only tested with Visual Studio 16 2019 x64.

```
cd src
cmake -B "build"
cmake --build "build" --config Release
```