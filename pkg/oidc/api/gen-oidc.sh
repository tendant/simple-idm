# gen handler code
echo "auto gen oidc.gen.go at oidc"
# -o output file location
# -p expected package name
# yaml file
goapi-gen -o oidc.gen.go -p api oidc.yaml
