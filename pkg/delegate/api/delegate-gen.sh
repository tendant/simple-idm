#!/bin/bash
# gen delegate code
echo "auto gen delegate.gen.go at delegate"
# -o output file location
# -p expected package name
# yaml file
goapi-gen -o delegate.gen.go -p api delegate.yaml

echo "copy delegate yaml to openapi cmd"