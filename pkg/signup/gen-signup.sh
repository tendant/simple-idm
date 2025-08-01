# gen handler code
echo "auto gen signup.gen.go at signup"
# -o output file location
# -p expected package name
# yaml file
goapi-gen -o signup.gen.go -p signup signup.yaml
