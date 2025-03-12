# gen handler code
echo "auto gen twofa.gen.go at twofa"
# -o output file location
# -p expected package name
# yaml file
goapi-gen -o twofa.gen.go -p api twofa.yaml
