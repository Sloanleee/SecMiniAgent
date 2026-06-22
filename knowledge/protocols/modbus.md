# Modbus

Modbus is an industrial protocol commonly associated with TCP port 502. It is often used for PLC and industrial gateway communication.

## Security Relevance

Unexpected access to TCP/502 can indicate unauthorized industrial protocol access, reconnaissance, or remote maintenance bypassing approved paths.

## Recommended Checks

- Verify whether the source host is approved for OT access.
- Confirm traffic passed through an approved jump host or maintenance gateway.
- Review whether write operations or configuration changes occurred.
