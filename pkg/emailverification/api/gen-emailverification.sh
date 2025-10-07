#!/bin/bash

# Generate OpenAPI server code for email verification API

oapi-codegen -generate types -package api emailverification.yaml > emailverification.gen.go
oapi-codegen -generate chi-server -package api emailverification.yaml >> emailverification.gen.go

echo "Email verification API code generated successfully"
