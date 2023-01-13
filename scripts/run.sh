#!/bin/bash

cp /vpn/gp-okta.conf.local /vpn/gp-okta.conf
sed -i -e "s|%VPN_URL%|${VPN_URL}|g" /vpn/gp-okta.conf
sed -i -e "s|%VPN_GATEWAY%|${VPN_GATEWAY}|g" /vpn/gp-okta.conf
sed -i -e "s|%OKTA_URL%|${OKTA_URL}|g" /vpn/gp-okta.conf
sed -i -e "s/%OKTA_USERNAME%/${OKTA_USERNAME}/g" /vpn/gp-okta.conf
sed -i -e "s/%OKTA_PASSWORD%/${OKTA_PASSWORD}/g" /vpn/gp-okta.conf
sed -i -e "s/%TOTP%/${TOTP}/g" /vpn/gp-okta.conf
sed -i -e "s|%ADDITIONAL_OPENCONNECT_ARGS%|${ADDITIONAL_OPENCONNECT_ARGS}|g" /vpn/gp-okta.conf

echo "Starting GP Okta VPN on https://${VPN_URL}"
python3 /vpn/gp-okta.py /vpn/gp-okta.conf

res=$?
if [ $res -ne 0 ]; then
    echo "OpenConnect could not successfully start. exiting..."
	exit $res
fi

SLEEP_TIME=10
echo "Sleeping for $SLEEP_TIME seconds so VPN can sort itself out."
sleep $SLEEP_TIME 

echo "Executing iptables nat rules."
iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE

echo "Executing additional commands."
$ADDITIONAL_COMMANDS

# Going to hold off for a bit and then check the status of openconnect
while [ true ]; do
    sleep 60
    pidof openconnect > /dev/null
    if [ $? -ne 0 ]; then
        echo "OpenConnect has quit. Exiting..."
        iptables -t nat -D POSTROUTING -o tun0 -j MASQUERADE
        exit 1
    else
        echo "OpenConnect still running. Continuing..."
    fi
done
