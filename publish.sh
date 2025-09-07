#!/usr/bin/env bash
set -e
git init
git config user.name "xiamsec"
git config user.email "siamdewan224@gmail.com"
git add -A
git commit -m "xiamsec" || true
git branch -M main
git remote remove origin 2>/dev/null || true
git remote add origin https://github.com/xiamsec/smart_subdomain_validator.git
git push -u origin main
