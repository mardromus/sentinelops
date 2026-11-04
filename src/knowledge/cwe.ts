/**
 * CWE entries used by the rules, each mapped to its OWASP Top 10 2021 category
 * (following OWASP's own CWE mapping) with a short remediation.
 */

export interface CweEntry {
  id: string; // "CWE-89"
  name: string;
  owasp: string;
  remediation: string;
}

const E = (id: string, name: string, owasp: string, remediation: string): CweEntry => ({
  id,
  name,
  owasp,
  remediation,
});

export const CWE: Record<string, CweEntry> = Object.fromEntries(
  [
    E('CWE-22', 'Path Traversal', 'A01:2021', 'Resolve the path against a base directory and reject escapes.'),
    E('CWE-601', 'Open Redirect', 'A01:2021', 'Only redirect to relative paths or allow-listed hosts.'),
    E('CWE-942', 'Permissive CORS Policy', 'A01:2021', 'Allow only trusted origins, never "*" with credentials.'),
    E('CWE-200', 'Exposure of Sensitive Information', 'A01:2021', 'Do not return internal details to clients.'),
    E('CWE-327', 'Broken or Risky Crypto Algorithm', 'A02:2021', 'Use SHA-256+ for integrity, bcrypt/argon2 for passwords.'),
    E('CWE-328', 'Weak Hash', 'A02:2021', 'Replace MD5/SHA-1 with SHA-256 (data) or bcrypt/argon2 (passwords).'),
    E('CWE-330', 'Insufficiently Random Values', 'A02:2021', 'Use crypto.randomBytes / crypto.randomUUID.'),
    E('CWE-798', 'Hard-coded Credentials', 'A07:2021', 'Move secrets to environment variables or a secret manager and rotate them.'),
    E('CWE-319', 'Cleartext Transmission', 'A02:2021', 'Use HTTPS/TLS.'),
    E('CWE-614', 'Cookie Without Secure Flag', 'A05:2021', 'Set secure: true, httpOnly: true, sameSite.'),
    E('CWE-1004', 'Cookie Without HttpOnly', 'A05:2021', 'Set httpOnly: true on session cookies.'),
    E('CWE-89', 'SQL Injection', 'A03:2021', 'Use parameterised queries.'),
    E('CWE-78', 'OS Command Injection', 'A03:2021', 'Use execFile/spawn with an argument array; validate input.'),
    E('CWE-95', 'Eval Injection', 'A03:2021', 'Never eval input; use JSON.parse or a safe parser.'),
    E('CWE-79', 'Cross-site Scripting', 'A03:2021', 'Escape output or use a template engine that escapes by default.'),
    E('CWE-1333', 'Regular Expression DoS', 'A06:2021', 'Avoid nested quantifiers on user input; upgrade the library.'),
    E('CWE-16', 'Configuration', 'A05:2021', 'Apply hardened configuration.'),
    E('CWE-250', 'Execution with Unnecessary Privileges', 'A05:2021', 'Run as a non-root user.'),
    E('CWE-693', 'Protection Mechanism Failure', 'A05:2021', 'Enable the standard protections (security headers).'),
    E('CWE-489', 'Active Debug Code', 'A05:2021', 'Disable debug mode in production.'),
    E('CWE-1104', 'Unmaintained Third-Party Components', 'A06:2021', 'Upgrade or replace the component.'),
    E('CWE-937', 'Using Components with Known Vulnerabilities', 'A06:2021', 'Upgrade to a fixed version.'),
    E('CWE-347', 'Improper Verification of Cryptographic Signature', 'A07:2021', 'Verify JWTs with jwt.verify and an explicit algorithms list.'),
    E('CWE-287', 'Improper Authentication', 'A07:2021', 'Use a vetted authentication flow.'),
    E('CWE-295', 'Improper Certificate Validation', 'A07:2021', 'Keep TLS verification on; pin a CA bundle instead of disabling checks.'),
    E('CWE-1321', 'Prototype Pollution', 'A08:2021', 'Use safe merge functions and reject __proto__ / constructor keys.'),
    E('CWE-494', 'Download of Code Without Integrity Check', 'A08:2021', 'Verify checksums/signatures; never pipe curl into sh.'),
    E('CWE-502', 'Deserialization of Untrusted Data', 'A08:2021', 'Do not deserialise untrusted input.'),
    E('CWE-532', 'Sensitive Information in Logs', 'A09:2021', 'Remove secrets from log statements.'),
    E('CWE-918', 'Server-Side Request Forgery', 'A10:2021', 'Allow-list destinations; block private address ranges.'),
  ].map((e) => [e.id, e]),
);

export function owaspForCwe(cwe: string): string | undefined {
  return CWE[cwe]?.owasp;
}
