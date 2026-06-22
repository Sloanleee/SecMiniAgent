# OT Rules

## OT_OFFICE_TO_CRITICAL_ASSET

This rule indicates that an office or IT source accessed a critical OT asset such as a PLC, HMI, SCADA node, engineering station, or OPC server.

Recommended response: verify authorization, check jump-host usage, and review firewall segmentation policy.

## OT_SUSPICIOUS_OT_PORT_ACCESS

This rule indicates access to a common industrial protocol port on a critical OT asset.

Recommended response: identify the protocol, review source authorization, and check whether the traffic included write or configuration operations.
