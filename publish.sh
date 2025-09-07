#!/usr/bin/env bash
set -e
git init
git config user.name "xiamsec"
git config user.email "you@example.com"
git add -A
git commit -m "Initial commit: Smart Subdomain Validator v1.6.2" || true
git branch -M main
git remote remove origin 2>/dev/null || true
git remote add origin https://github.com/xiamsec/smart_subdomain_validator.git
git push -u origin main
