# gen reimbursement code
echo "auto gen demo.gen.go at demo"
# -o output file location
# -p expected package name
# yaml file
goapi-gen -o demo.gen.go -p demo demo.yaml
