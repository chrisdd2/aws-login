#!/bin/bash

# generate cert
if [[ ! -f 'server.key' || ! -f 'server.crt' ]]; then
    openssl genrsa -out server.key 2048
    openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650
fi

export AWS_REGION='eu-west-1'
aws sts get-caller-identity
gow -e=go,mod,html,template,css run .