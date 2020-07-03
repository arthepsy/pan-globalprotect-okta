#!/usr/bin/env bash

container=$(docker ps -q -f name=gp-okta)
if [ -z "${container}" ]; then
    echo "VPN is not running!"
    exit 1
fi

# Watch output for close-down output
( timeout 30 docker logs -f --since 0s gp-okta & )

docker stop gp-okta > /dev/null

echo
echo
echo "VPN stopped."
