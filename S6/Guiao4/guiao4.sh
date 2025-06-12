#!/bin/bash
touch lisboa.txt; touch porto.txt; touch braga.txt
ls -l lisboa.txt
chmod 666 lisboa.txt
chmod u-w porto.txt
chmod go-r braga.txt
mkdir d1; mkdir d2
chmod go-x d2
ls -l