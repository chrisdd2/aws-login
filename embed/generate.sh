#!/bin/bash

targetDir="$(pwd)"
rm -rf assets

cd ../front/aws-login
npm ci
npm run build
cp -R dist "$targetDir/assets"
