# gen handler code
echo "auto gen auth.gen.go at auth"
# -o output file location
# -p expected package name
# yaml file
goapi-gen -o auth.gen.go -p auth auth.yaml
