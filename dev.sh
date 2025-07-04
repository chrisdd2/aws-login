#!/bin/bash
export APP_CLIENT_ID='< github oauth client id>'
export APP_CLIENT_SECRET='< github oauth client secret>'
# example creds for aws
export AWS_ACCESS_KEY_ID='<>'
export AWS_SECRET_ACCESS_KEY='<>'
export AWS_REGION='<region>'
export APP_LISTEN_ADDR="0.0.0.0:8090"
export APP_SIGN_KEY='<some key>'
# generate root token on startup
export APP_GENERATE_TOKEN=1
# readable logs for humans
export APP_DEVELOPMENT_MODE=1

aws sts get-caller-identity
gow -e=go,mod,html,template,css run .