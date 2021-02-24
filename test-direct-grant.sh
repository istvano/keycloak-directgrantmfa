#!/bin/bash

function login {
  set -x
  OTP_SEND_TOKEN=`curl -s -k --data 'username=alice&password=password&grant_type=password&client_id=demo-client&client_secret=8a899f1a-e391-4bbf-b29f-35f103fda84d' http://localhost:8080/auth/realms/demo/protocol/openid-connect/token |  jq -r  '.mfa_token'`
  set +x
  echo Reveived token that can be used to trigger an mfa send to the user
  printf '{"key":"%s"}' "$OTP_SEND_TOKEN" | jq
}

function send_otp {
  set -x
  VERIFY_TOKEN=`curl -s -k -H 'Accept: application/json' -H 'Content-Type: application/json' -G -d key=$OTP_SEND_TOKEN http://localhost:8080/auth/realms/demo/login-actions/action-token | jq -r '.verify_token'`
  set +x
  echo Received otp verify token which can be used to verify otp code received by the user
  printf '{"mfa_verify_token":"%s"}' "$VERIFY_TOKEN" | jq
}

function verify_otp {
  set -x
  curl -s -k -H "Accept: application/json" -H "Content-Type: application/json" -G -d scope="phone" -d otp=1234567890 -d key=$VERIFY_TOKEN http://localhost:8080/auth/realms/demo/login-actions/action-token | jq
  set +x
}

login
send_otp
verify_otp
