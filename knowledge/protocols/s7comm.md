# S7comm

S7comm is commonly associated with Siemens PLC communication and often uses TCP port 102.

## Security Relevance

Unexpected TCP/102 access to engineering stations or PLCs should be reviewed because it may involve control-system discovery or engineering access.

## Recommended Checks

- Confirm the source is an authorized engineering workstation.
- Review change windows and engineering activity records.
- Check segmentation between office, DMZ, and production zones.
