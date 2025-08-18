#!/bin/bash
# gen handler code
echo "auto gen externalprovider.gen.go at externalprovider"
# -o output file location
# -p expected package name
# yaml file
goapi-gen -o externalprovider.gen.go -p api externalprovider.yaml
