#!/bin/bash
# gen impersonate code
echo "auto gen impersonate.gen.go at impersonate"
# -o output file location
# -p expected package name
# yaml file
goapi-gen -o ./impersonate.gen.go -p impersonate impersonateapi.yaml

echo "copy impersonate yaml to openapi cmd"
