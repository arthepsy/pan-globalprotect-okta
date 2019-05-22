#!/usr/bin/env bash

basedir=$(dirname $0)
conf_username=`grep username "${basedir}/gp-okta.conf" | awk -F \= '{print $2}' | tr -d " "`
conf_password=`grep password "${basedir}/gp-okta.conf" | awk -F \= '{print $2}' | tr -d " "`
totp_okta=`grep totp.okta "${basedir}/gp-okta.conf" | awk -F \= '{print $2}' | tr -d " "`
totp_google=`grep totp.google "${basedir}/gp-okta.conf" | awk -F \= '{print $2}' | tr -d " "`

haystack="okta google"

if [[ -z "${totp_okta}" && -z "${totp_google}" ]]; then
    read -p "Enter Second auth numbers (okta or google), (prepend with needed provider e.g okta_1234): " totp
    if [[ "${totp}" ]]; then
        totp_choice=`echo ${totp} | awk  -F _ '{ print $1 }'`
        totp_numbers=`echo ${totp} | awk  -F _ '{ print $2 }'`
        if [[ -n "echo $haystack|grep $totp_choice" ]]; then
            echo "${totp_choice}"
            if [[ "${totp_numbers}" && ${totp_choice} ]]; then
                sed -i "s/totp.${totp_choice}.*/totp.${totp_choice} = ${totp_numbers}/g" gp-okta.conf
            fi
        else
            echo "Unsupported second auth choosed"
            exit 1
        fi

    else
        echo "Something failed with parsing second auth"
        exit 1
    fi

fi

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
fi

echo


docker run \
    -d \
    --rm \
    --privileged \
    --net=host \
    --cap-add=NET_ADMIN \
    --device /dev/net/tun \
    -e GP_PASSWORD=${GP_PASSWORD} \
    -e GP_USERNAME=${GP_USERNAME} \
    -v /etc/resolv.conf:/etc/resolv.conf \
    -v ${basedir}:/openconnect/gp-okta \
    gp-okta
