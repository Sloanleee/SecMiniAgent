# Remote Maintenance Risks

Wind farm remote maintenance paths should be controlled through approved VPN, jump hosts, MFA, and change windows.

## Security Relevance

Unexpected remote access may indicate credential misuse, weak segmentation, or direct access to operational systems.

## Recommended Checks

- Confirm maintenance ticket and change window.
- Verify source account, VPN session, and jump-host record.
- Review whether the destination is SCADA, engineering, substation, or turbine control infrastructure.
