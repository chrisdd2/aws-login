#!/bin/bash

export AWS_REGION='eu-west-1'
aws sts get-caller-identity
gow -e=go,mod,html,template,css run .