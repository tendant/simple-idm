#!/bin/bash

goapi-gen -o role.gen.go -p api role.yaml

echo "auto gen role.gen.go at role"
