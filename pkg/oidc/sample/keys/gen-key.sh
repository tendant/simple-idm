openssl genpkey -algorithm RSA -out private.pem
openssl rsa -in private.pem -pubout -out public.pem
