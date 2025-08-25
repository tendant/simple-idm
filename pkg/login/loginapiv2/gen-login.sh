# gen handler code
echo "auto gen login.gen.go at login"
# -o output file location
# -p expected package name
# yaml file
goapi-gen -o login.gen.go -p apiv2 login.yaml
