# pan-globalprotect-okta

Command-line client for PaloAlto Networks' GlobalProtect VPN, integrated with OKTA.
This utility will do the _authentication dance_ with OKTA to retrieve cookie,
which will be passed to [OpenConnect](https://github.com/openconnect/openconnect)
for creating actual VPN connection. Compatible with Python 2 and 3. Tested on
FreeBSD, Linux and MacOS X. Tested with OpenConnect 8.00 - 8.10.

It also supports multiple second factor authentication implementations like Google, OKTA, YubiKey, SMS, etc.
TOPT authentication can work without user interaction, if initial secret is provided. 
Otherwise, it will ask for generated code.

To gather TOTP secret, there are two possibilities - either scan the provided QR
code with _normal_ QR code scanner and write down the secret. Or create backup
from current OTP application in phone. Some applications have this feature, but
some don't. For example, andOTP on Android do support this feature.

## usage
This utility depends on [requests](http://www.python-requests.org/) and [lxml](https://lxml.de/)
Python libraries. If TOTP secret is being used, then [pyotp](https://github.com/pyotp/pyotp)
is also required. For YubiKey, [fido2](https://github.com/Yubico/python-fido2) is required.

```
   ./gp-okta.py gp-okta.conf
```

## docker

Build Docker image before running container:
```
docker build -t gp-okta .
```

Edit gp-okta.conf and launch Docker container:
```
sh run-docker.sh
```

## configuration

Configuration file should be self-explanatory. Options can be overridden with
`GP_` prefixed respective environment variables, e.g., `GP_PASSWORD` will
override `password` option in configuration file.

## changelog
### v1.00 (2020-05-xx)
- new MFA: push, Symantec, WebAuthN/YubiKey
- GnuGP config encryption
- direct gateway authentication
- second authentication dance
- use client certificates
- verify server certificates
- type checking

### v0.99 (2019-02-14)
- supported MFA: OKTA, Google, SMS
- interactive and hard-coded MFA
- configurable gateway choice
- Python2 and Python3 support
- Dockerfile example
- workarounds for known issues

## known issues

If `openconnect` returns with `ioctl` or `fgets (stdin): Resource temporarily unavailable`
error, then this `openconnect` version requires different `openconnect_fmt` than detected
or manually specified. Run `openconnect` manually and paste line-by-line required options
to figure out required `openconnect_fmt`. Also, please, open an issue and report it.
