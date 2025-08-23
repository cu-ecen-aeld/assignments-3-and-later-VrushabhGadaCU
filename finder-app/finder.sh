#!/bin/sh

if [ $# -ge 2 ]
then
    if [ $# -gt 2 ]
    then
        echo "Only two arguments are used first as directory and second as string to search for in files present in directory\n"
    fi

    filesdir=$1
    searchstr=$2
    if [ ! -d "$filesdir" ]
    then
        echo "Directory $1 does not exist enter valid directory"
        exit 1
    fi
    fileCount=$(find -L "$filesdir" -type f  | wc -l)
    matchLine=$(grep -rI "$searchstr" "$filesdir" | wc -l)
    echo "The number of files are $fileCount and the number of matching lines are $matchLine"
else
    echo "Please enter First argument as File directory and second argument as string to search for in files present in directory"
    exit 1
fi