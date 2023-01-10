#!/bin/bash

# Use like: bash ~/scripts/unblob.sh Firmware_Image.bin

mkdir unblob_output
sudo docker run \
  --rm \
  -v $(pwd)/unblob_output:/data/output \
  -v $(pwd):/data/input \
  ghcr.io/onekey-sec/unblob:latest /data/input/$1
