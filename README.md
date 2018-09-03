# pan-globalprotect-okta

Command-line client for PaloAlto Networks' GlobalProtect VPN, integrated with OKTA. 
This utility will do the _authentication dance_ with OKTA to retrieve `portal-userauthcookie`,
which will be passed to [OpenConnect with PAN GlobalProtect support](https://github.com/dlenski/openconnect)
for creating actual VPN connection.

It also supports Google and OKTA two factor authentication and can work without
user interaction, if initial TOTP secret is provided. Otherwise, it will ask for
generated code. If this feature will be used, [pyotp](https://github.com/pyotp/pyotp)
dependency is required.

To gather TOTP secret, there are two possibilities - either scan the provided QR
code with _normal_ QR code scanner and write down the secret. Or create backup
from current OTP application in phone. Some applications have this feature, but
some don't. For example, andOTP on Android do support this feature.

## usage
```
   ./gp-okta.py gp-okta.conf
```

## configuration

Configuration file should be self-explanatory. Options can be overridden with
`GP_` prefixed respective environment variables, e.g., `GP_PASSWORD` will
override `username` option in configuration file.

## known issues

If `openconnect` returns with `ioctl` error, then this version has a bug, which
requires to prefix stdin input with a newline. Set `bug.nl=1` in configuration
file.
