# ykfipsconf
A Python wrapper for the [ykman](https://github.com/Yubico/yubikey-manager) tool, made to take an unlocked YubiKey and enable fips mode on it.

## Caveats:
Most provisioning operations with yubikeys can be done in 2 steps:
1. provision & lock devices (OTP, PIV slots mainly)
2. Issue to users and allow for some self registration of user driven flows (WebAuthn FIDO2 registrations etc.)

FIPS mode devices are more restrictive: instead of allowing a user to self register FIDO, the "Crypto Officer" is supposed to do that for them, then lock the YubiKey on their behalf.  This means, the Crypto Officer is not just provisioning secrets but they also assign the key to a user at the point of provisioning.

Duo, Okta and Google all permit this in their administrative workflows, though this functionality is limited typically to allowing administrators to register 1 FIDO key on behalf of each user.

## Provisioning Process Notes
In order to "enable FIPS mode" we only have a few possible ways to configure the key and when you run this tool, these things will be ensured:
1. In order for the device to be "FIPS mode" you must enable all required apps in fips mode, that means the mode MUST be OTP+CCID+FIDO or it will not show as being in FIPS mode.
2. U2F registration must be done by unlocking the FIDO slot, and likely done on behalf of the user by the Crypto Officer.  Once the device is *locked* no further registrations can happen (no user self service webauthn registrations.)

A json config file must be present in `/etc/ykConfig/secrets.json` that looks like so:

```
{
    "ykConfig": {
    "otp_access_code" : "012345678910",
    "oath_password": "TheQuickBrownFoxJumpedOverTheLazyDog1",
    "fido_admin_pin" : "pin4fips123",
    "u2f_pin" : "012345678910"
    }
}
```

## Usage 

```./ykConfig.py -o output.csv```

Once you've executed the above, the dialogs should guide you through provisioning.

All the Crypto Officer should have to do is hit <kbd>Enter</kbd> in between inserting and removing YubiKeys (if the modes are configured correctly.) If there is a required mode change due to non-homogenous factory configurations or the like, you will be prompted to remove and reinsert the token, and press <kbd>Enter</kbd> again.

### Resetting otp state

```./ykConfig.py -r```

Resetting will only work if the OATH and OTP passwords are correct in the config.  This will delete the OTP slots (1&2), removing any existing pins, as well as the OATH configuration, removing the password there as well.  

U2F slots are currently out of scope for the reset flag, as resetting the app causes the key to leave FIPS mode permanently.

## Additional References:
[Yubikey Fips Series Technical Manual](https://support.yubico.com/support/solutions/articles/15000011059-yubikey-fips-series-technical-manual)

[Yubico Fips series deployment considerations](https://support.yubico.com/support/solutions/articles/15000022275-yubikey-fips-series-deployment-considerations)

### Note: 
External contributions to the project should be subject to Dropbox Contributor License Agreement (CLA).
