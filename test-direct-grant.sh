#!/bin/sh
# This is a comment!
echo 1. curl -s -k --data 'username=alice&password=password&grant_type=password&client_id=demo-client&client_secret=8a899f1a-e391-4bbf-b29f-35f103fda84d' http://localhost:8080/auth/realms/demo/protocol/openid-connect/token
OTP_SEND_TOKEN="$(curl -s -k --data 'username=alice&password=password&grant_type=password&client_id=demo-client&client_secret=8a899f1a-e391-4bbf-b29f-35f103fda84d' http://localhost:8080/auth/realms/demo/protocol/openid-connect/token |  jq -r  '.mfa_token')"; \
echo Reveived token
echo {\"mfa_send_token\":\"$OTP_SEND_TOKEN\"} | jq
echo 2. curl -s -k -H 'Accept: application/json' -H 'Content-Type: application/json' -G -d key=$OTP_SEND_TOKEN http://localhost:8080/auth/realms/demo/login-actions/action-token
VERIFY_TOKEN="$(curl -s -k -H 'Accept: application/json' -H 'Content-Type: application/json' -G -d key=$OTP_SEND_TOKEN http://localhost:8080/auth/realms/demo/login-actions/action-token | jq -r '.verify_token')"; \
echo Received otp verify token
echo {\"mfa_verify_token\":\"$VERIFY_TOKEN\"} | jq
echo 3. curl -s -k -H "Accept: application/json" -H "Content-Type: application/json" -G -d scope="phone" -d otp=1234567890 -d key=$VERIFY_TOKEN http://localhost:8080/auth/realms/demo/login-actions/action-token
curl -s -k -H "Accept: application/json" -H "Content-Type: application/json" -G -d scope="phone" -d otp=1234567890 -d key=$VERIFY_TOKEN http://localhost:8080/auth/realms/demo/login-actions/action-token | jq
