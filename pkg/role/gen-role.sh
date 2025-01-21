#!/bin/bash

goapi-gen -o role.gen.go -p role role.yaml

echo "auto gen role.gen.go at role"
