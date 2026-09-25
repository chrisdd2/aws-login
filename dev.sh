#!/bin/bash

export AWS_REGION='eu-west-1'
if [ -f .env ]; then
    set -a
    source .env
    set +a
fi
aws sts get-caller-identity
gow -e=go,mod,html,template,css run ./cmd/cli "$@"