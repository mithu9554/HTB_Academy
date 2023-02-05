#!/bin/bash

word1=$1
word2=$2

word1_md5=$(echo -n "${word1}" | md5sum | cut -d ' ' -f 1)
word2_md5=$(echo -n "${word2}" | md5sum | cut -d ' ' -f 1)
word=$(echo -n "$word1_md5:$word2_md5")
word_base64=$(echo -n "${word}" | base64)

echo "$word_base64"
