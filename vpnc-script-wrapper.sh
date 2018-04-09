#!/bin/sh

_VPNC_SCRIPT="/usr/local/sbin/vpnc-script"

_ROUTES="
10.0.0.0/255.0.0.0/8
192.168.0.0/255.255.0.0/16
"
_DOMAINS="
example.com
"

OIFS=$IFS; NLIFS='
'

_split() {
	_line=$1; IFS=$2; shift 2
	read -r -- "$@" <<-EOF
		${_line}
	EOF
}

_get_unbound() {
        command -v /usr/local/sbin/unbound-control >/dev/null 2>&1 \
		&& echo "/usr/local/sbin/unbound-control" && return 0
        command -v unbound-control >/dev/null 2>&1 \
		&& echo "unbound-control"  && return 0
        return 1
}

output_routes()
{
	if [ -n "${CISCO_SPLIT_INC}" ]; then
		_i=0
		while [ ${_i} -lt ${CISCO_SPLIT_INC} ] ; do
			eval _addr="\${CISCO_SPLIT_INC_${_i}_ADDR}"
			eval _mask="\${CISCO_SPLIT_INC_${_i}_MASK}"
			eval _masklen="\${CISCO_SPLIT_INC_${_i}_MASKLEN}"
			echo "orig.route: ${_addr}/${_masklen}"
			_i=$(expr ${_i} + 1)
		done
	fi
}

adjust_routes()
{
	for _k in $(env | grep ^CISCO_SPLIT_INC | cut -d '=' -f 1); do
		unset ${_k}
	done
	IFS=$NLIFS
	_i=0;
	for _line in ${_ROUTES}; do
		_split "${_line}" ' ' _route _
		_split "${_route}" '/' _addr _mask _masklen _
		export CISCO_SPLIT_INC_${_i}_ADDR="${_addr}"
		export CISCO_SPLIT_INC_${_i}_MASK="${_mask}"
		export CISCO_SPLIT_INC_${_i}_MASKLEN="${_masklen}"
		_i=$(expr ${_i} + 1)
	done
	export CISCO_SPLIT_INC=${_i}
	IFS=$OIFS
}

output_dns()
{
	echo "orig.dns: ${INTERNAL_IP4_DNS}"
	echo "orig.domain: ${CISCO_DEF_DOMAIN}"
}

adjust_dns()
{
	_dns="${INTERNAL_IP4_DNS}"
	unset CISCO_DEF_DOMAIN
	unset INTERNAL_IP4_DNS
	[ -z "${_dns}" ] && return
	_unbound=$(_get_unbound) || { echo "err: unbound not found" >&2 && exit 1; }
	IFS=$NLIFS
	for _line in ${_DOMAINS}; do
		_split "${_line}" ' ' _domain _
		if [ X"${reason}" = X"connect" ]; then
			${_unbound} forward_add +i "${_domain}" "${_dns}"
			${_unbound} flush_requestlist
			${_unbound} flush_zone "${_domain}"
		elif [ X"${reason}" = X"disconnect" ]; then
			${_unbound} forward_remove +i "${_domain}" 
			${_unbound} flush_zone "${_domain}"
			${_unbound} flush_requestlist 
		fi
	done
	IFS=$OIFS
}

output_routes
adjust_routes
output_dns
adjust_dns

${_VPNC_SCRIPT} $@

