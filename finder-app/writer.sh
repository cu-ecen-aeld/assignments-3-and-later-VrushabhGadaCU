#!/bin/bash

if [ $# -ge 2 ]
then
    if [ $# -gt 2 ]
    then
        echo "Only two arguments are used first as File path and second as Text to save in te file\n"
    fi
    
    writefile=$1
    writestr=$2
    dir_path=$(dirname "$writefile")
    if [ ! -d "$dir_path" ]
    then
        mkdir -p "$dir_path"
    fi
    echo -n "$writestr" > "$writefile"
    
else
    echo "Please enter First argument as File path and second as Text to save in te file"
    exit 1
fi