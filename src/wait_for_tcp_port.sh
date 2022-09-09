#!/bin/bash
URL="$1"
while [[ "$(curl -k -s -o /dev/null -w ''%{http_code}'' ${URL})" != "200" ]]; do sleep 5; done
