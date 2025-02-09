# gen handler code
echo "auto gen iam.gen.go at iam"
# -o output file location
# -p expected package name
# yaml file
goapi-gen -o iam.gen.go -p iam iam.yaml
