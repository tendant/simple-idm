# gen handler code
echo "auto gen profile.gen.go at profile"
# -o output file location
# -p expected package name
# yaml file
goapi-gen -o profile.gen.go -p api profile.yaml
