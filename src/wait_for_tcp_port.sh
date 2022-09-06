bash -c 'while [[ "$(curl -k -s -o /dev/null -w ''%{http_code}'' https://localhost:443)" != "200" ]]; do sleep 5; done'
