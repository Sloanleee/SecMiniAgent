# ioc_hunting
Description: Hunt local IOC values across parsed security alerts.

Use `extract_iocs` to parse IOC files and `match_iocs` to compare IOC values against alert source and destination IP fields.

Report matched IOC, alert id, source, destination, and immediate defensive action such as blocking, monitoring, or evidence collection.
