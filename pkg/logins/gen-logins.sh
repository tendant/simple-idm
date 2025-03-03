## CRUD for all logins
# gen handler code
echo "auto gen logins.gen.go at logins"
# -o output file location
# -p expected package name
# yaml file
goapi-gen -o logins.gen.go -p logins logins.yaml
    