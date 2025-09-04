# gen handler code
echo "auto gen oauth2client.gen.go at oauth2client"
# -o output file location
# -p expected package name
# yaml file
goapi-gen -o oauth2client.gen.go -p api oauth2client.yaml
