# Memory Investigation Notes

using volatility

```
for plugin in windows.netscan.NetScan windows.pstree.PsTree windows.pslist.PsList windows.cmdline.CmdLine windows.filescan.FileScan windows.dlllist.DllList; do vol -q -f FM-TETRIS.mem $plugin > fm-tetris.$plugin.txt; done
strings FM-TETRIS.mem > fm-tetris.strings-asc.txt
strings -e l FM-TETRIS.mem > fm-tetris.strings-unile.txt
strings -e b FM-TETRIS.mem > fm-tetris.strings-unibe.txt
grep 167.172.201.123 fm-tetris.windows.netscan.NetScan.txt
grep analytics.exe fm-tetris.windows.netscan.NetScan.txt
grep -C 3 analytics.exe fm-tetris.windows.pstree.PsTree.txt
grep analytics.exe fm-tetris.windows.filescan.FileScan.txt
grep bJKRJiSAnPkf.e fm-tetris.windows.filescan.FileScan.txt
grep -C 5 analytics.exe fm-tetris.windows.dlllist.DllList.txt
grep analytics.exe fm-tetris.windows.cmdline.CmdLine.txt
grep -i analytics.exe fm-tetris.strings-*.txt
grep -i -h 'windows\\system32\\analytics' fm-tetris.strings-*.txt | sort -u
grep -i -h bJKRJiSAnPkf fm-tetris.strings-*.txt | sort -u
```

Bonues

```
grep midnitemeerkats fm-tetris.*txt
grep GSMCRD35ch4 fm-tetris.*txt | sort -u
grep lolcats.org access.log
TZ=America/Los_Angeles awk '/lolcats.org/ {print strftime("%T", $1), $3, $7, $9}' access.log
connect-lab
```
