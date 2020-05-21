# pan-globalprotect-okta

Command-line client for PaloAlto Networks' GlobalProtect VPN, integrated with OKTA.
This utility will do the _authentication dance_ with OKTA to retrieve `portal-userauthcookie`,
which will be passed to [OpenConnect with PAN GlobalProtect support](https://github.com/dlenski/openconnect)
for creating actual VPN connection. Compatible with Python 2 and 3. Tested on
FreeBSD, Linux and MacOS X.

It also supports Google and OKTA two factor authentication and can work without
user interaction, if initial TOTP secret is provided. Otherwise, it will ask for
generated code.

To gather TOTP secret, there are two possibilities - either scan the provided QR
code with _normal_ QR code scanner and write down the secret. Or create backup
from current OTP application in phone. Some applications have this feature, but
some don't. For example, andOTP on Android do support this feature.

## usage
This utility depends on [requests](http://www.python-requests.org/) and [lxml](https://lxml.de/)
Python libraries. If TOTP secret is being used, then [pyotp](https://github.com/pyotp/pyotp)
is also required.

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
or manually specified. Run `openconnect` manually and paste line-by-line required options.

