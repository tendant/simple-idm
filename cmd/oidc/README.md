curl -i "http://localhost:4002/oidc/authorize?response_type=code&client_id=myclient&redirect_uri=http://localhost:4002/oauth2/callback&scope=openid&state=abcdefgh"

http://localhost:3000/oidc/authorize?response_type=code&client_id=myclient&redirect_uri=http://localhost:3000/oauth2/callback&scope=openid&state=abcdefgh

curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" "http://localhost:4002/oidc/userinfo"
