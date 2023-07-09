#!/bin/bash

echo "file: "
read var1

sed  -i  's|^|hash md5|g' $var1
