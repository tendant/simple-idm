# gen handler code
echo "auto gen user.gen.go at user"
# -o output file location
# -p expected package name
# yaml file
goapi-gen -o user.gen.go -p user user.yaml
