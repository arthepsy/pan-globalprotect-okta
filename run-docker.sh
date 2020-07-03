#!/usr/bin/env bash

conf_username=$(grep "^username" gp-okta.conf | awk -F \= '{print $2}' | tr -d " ")
conf_password=$(grep "^password" gp-okta.conf | awk -F \= '{print $2}' | tr -d " ")

### detect where username is filled in
if [[ "${conf_username}" ]]; then
    GP_USERNAME=${conf_username}
fi

if [[ -z "${conf_username}" && -z "${GP_USERNAME}" ]]; then
    read -p "Enter Okta username: " GP_USERNAME
fi

### detect where password is filled in
if [[ "${conf_password}" ]]; then
    GP_PASSWORD=${conf_password}
fi

if [[ -z "${conf_password}" && -z "${GP_PASSWORD}" ]]; then
    read -s -p "Enter Okta password: " GP_PASSWORD
    echo
fi

# If no TOTP secrets are specified, prompt for OTP.
totp_secrets=$(grep "^totp." gp-okta.conf | awk -F \= '{print $2}' | tr -d " ")
if [[ -z "${totp_secrets}" ]]; then
    read -p "Enter MFA OTP code: " totp
fi

echo

docker run \
    -d \
    --name=gp-okta \
    --rm \
    --privileged \
    --net=host \
    --cap-add=NET_ADMIN \
    --device /dev/net/tun \
    -e GP_USERNAME=${GP_USERNAME} \
    -e GP_PASSWORD=${GP_PASSWORD} \
    -e GP_TOTP_CODE=${totp} \
    -e GP_EXECUTE=1 \
    -e GP_OPENCONNECT_CMD=/usr/local/sbin/openconnect \
    -v /etc/resolv.conf:/etc/resolv.conf \
    -v ${PWD}/gp-okta.conf:/etc/gp-okta.conf \
    gp-okta \
    > /dev/null

# Watch output for successful, for a little while at least
( timeout 30 docker logs -f gp-okta & ) | sed '/ESP tunnel connected/q'

# If container is gone, something went awry
echo
echo
if [ -z "$(docker ps -q -f name=gp-okta)" ]; then
    echo
    echo
    echo "VPN failed to start!"
    exit 1
else
    echo "VPN running"
    exit 0
fi
