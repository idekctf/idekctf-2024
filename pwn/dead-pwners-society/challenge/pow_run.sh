#!/bin/bash

echo "=== Solve a POW before accessing the challenge ===" 
echo "POW solver can be obtained here: https://github.com/Aplet123/kctf-pow"
echo "Solve using: kctf-pow solve <pow>"

./kctf-pow ask 60000

if [ $? -eq 0 ] 
then
    ./run.sh
fi
