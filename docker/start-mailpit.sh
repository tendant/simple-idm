docker run -d \
       --name=mailpit \
       --restart unless-stopped \
       -e MP_SMTP_AUTH_ALLOW_INSECURE=true \
       -e MP_SMTP_AUTH="noreply@example.com:pwd" \
       -e TZ=America/Los_Angeles \
       -p 8025:8025 \
       -p 1025:1025 \
       axllent/mailpit