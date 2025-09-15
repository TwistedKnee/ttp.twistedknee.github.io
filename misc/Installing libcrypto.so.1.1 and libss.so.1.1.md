
https://stackoverflow.com/questions/72133316/libssl-so-1-1-cannot-open-shared-object-file-no-such-file-or-directory

From above ^ needed this for a version of mongo for cli access, commands to install to avoid libcrypto issues:

```
mkdir $HOME/opt && cd $HOME/opt
# Download a supported openssl version. e.g., openssl-1.1.1o.tar.gz or openssl-1.1.1t.tar.gz
wget https://www.openssl.org/source/openssl-1.1.1o.tar.gz
tar -zxvf openssl-1.1.1o.tar.gz
cd openssl-1.1.1o
./config && make && make test
mkdir $HOME/opt/lib
mv $HOME/opt/openssl-1.1.1o/libcrypto.so.1.1 $HOME/opt/lib/
mv $HOME/opt/openssl-1.1.1o/libssl.so.1.1 $HOME/opt/lib/


export LD_LIBRARY_PATH=$HOME/opt/lib:$LD_LIBRARY_PATH
```

even if it says compilation failed, the libss and libcrypto shared libraries are located in the folder for moving over and being exported 
