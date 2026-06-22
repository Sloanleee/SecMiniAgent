# OPC UA

OPC UA is an industrial data exchange protocol commonly associated with TCP port 4840.

## Security Relevance

Unexpected OPC UA sessions may expose process data or indicate unauthorized data collection from industrial systems.

## Recommended Checks

- Verify client identity and certificate trust.
- Confirm the access path is expected for the asset zone.
- Review whether the session originated from an office or remote-maintenance network.
