#!/bin/sh
_cdir=$(cd -- "$(dirname "$0")" && pwd)
command -v mypy > /dev/null 2>&1
if [ $? -ne 0 ]; then
	echo "err: mypy (Optional Static Typing for Python) not found."
	exit 1
fi
for _pyver in 2.7 3.7; do
	echo "--- Python ${_pyver}"
	mypy --no-error-summary --strict --warn-unreachable --python-version "${_pyver}" "${_cdir}/../gp-okta.py"
done
