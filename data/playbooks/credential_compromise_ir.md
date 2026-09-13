# Incident Response — Credential Compromise

## Detection
- Multiple failed_login events followed by successful_login from same source IP
- Login from unusual geographic location

## Containment
1. Disable affected account
2. Block source IP
3. Revoke active sessions

## Eradication
- Force password reset
- Review account permissions and group membership

## Recovery
- Re-enable account after MFA enrollment
- Monitor for 72 hours

## Lessons Learned
Document attack timeline, IOCs, and MITRE techniques in formal incident report.
