/**
 * OWASP Top 10 (2021): the reference taxonomy every finding is mapped to.
 * Summaries and prevention guidance are written for developers fixing code.
 */

export interface OwaspCategory {
  id: string; // "A03:2021"
  name: string;
  summary: string;
  prevention: string[];
  url: string;
}

export const OWASP_TOP10_2021: OwaspCategory[] = [
  {
    id: 'A01:2021',
    name: 'Broken Access Control',
    summary:
      'Users can act outside their intended permissions: reading other users’ data, path traversal, ' +
      'insecure direct object references, open redirects, permissive CORS.',
    prevention: [
      'Deny by default; enforce authorisation on the server for every request.',
      'Resolve file paths against a fixed base directory and reject anything that escapes it.',
      'Validate redirect targets against an allow-list.',
      'Restrict CORS origins to the ones you trust.',
    ],
    url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
  },
  {
    id: 'A02:2021',
    name: 'Cryptographic Failures',
    summary:
      'Sensitive data exposed through weak or missing cryptography: MD5/SHA-1 for passwords, predictable ' +
      'random numbers for tokens, hard-coded keys, data sent in clear text.',
    prevention: [
      'Hash passwords with bcrypt, scrypt or Argon2; never with fast hashes.',
      'Use crypto.randomBytes / secrets for tokens, never Math.random.',
      'Keep keys out of source code; load them from a secret manager.',
      'Use TLS everywhere and set the Secure flag on cookies.',
    ],
    url: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
  },
  {
    id: 'A03:2021',
    name: 'Injection',
    summary:
      'Untrusted data is sent to an interpreter as part of a command or query: SQL, OS command, ' +
      'code evaluation, cross-site scripting.',
    prevention: [
      'Use parameterised queries / prepared statements.',
      'Never build shell commands from input; use execFile/spawn with an argument array.',
      'Do not eval input; parse it (JSON.parse) instead.',
      'Encode output for its context and use templating that escapes by default.',
    ],
    url: 'https://owasp.org/Top10/A03_2021-Injection/',
  },
  {
    id: 'A04:2021',
    name: 'Insecure Design',
    summary: 'Missing or ineffective security controls by design, e.g. no rate limiting or unsafe defaults.',
    prevention: ['Threat-model critical flows.', 'Add rate limits and secure defaults.'],
    url: 'https://owasp.org/Top10/A04_2021-Insecure_Design/',
  },
  {
    id: 'A05:2021',
    name: 'Security Misconfiguration',
    summary:
      'Insecure defaults or settings: missing security headers, verbose errors, containers running as ' +
      'root, debug mode in production, permissive cookie flags.',
    prevention: [
      'Use hardened defaults (helmet for Express, non-root containers, pinned base images).',
      'Disable debug output and stack traces in production.',
      'Set HttpOnly, Secure and SameSite on session cookies.',
    ],
    url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
  },
  {
    id: 'A06:2021',
    name: 'Vulnerable and Outdated Components',
    summary: 'Libraries, frameworks or images with known vulnerabilities are in use.',
    prevention: [
      'Inventory dependencies and monitor advisories (OSV, GitHub Advisory Database).',
      'Upgrade to the fixed versions; remove unused packages.',
      'Fail the build on critical known vulnerabilities.',
    ],
    url: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
  },
  {
    id: 'A07:2021',
    name: 'Identification and Authentication Failures',
    summary: 'Weak authentication or session handling, e.g. JWTs accepted without verification.',
    prevention: [
      'Verify JWT signatures with an explicit algorithm list; never trust decode().',
      'Use proven session management and multi-factor authentication.',
    ],
    url: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
  },
  {
    id: 'A08:2021',
    name: 'Software and Data Integrity Failures',
    summary:
      'Code or data is trusted without integrity checks: insecure deserialisation, piping remote scripts ' +
      'into a shell, prototype pollution through unsafe merges.',
    prevention: [
      'Verify signatures / checksums of anything downloaded during builds.',
      'Avoid deserialising untrusted data; use safe merge functions.',
    ],
    url: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
  },
  {
    id: 'A09:2021',
    name: 'Security Logging and Monitoring Failures',
    summary: 'Attacks go unnoticed because events are not logged, or secrets leak into logs.',
    prevention: ['Log security events centrally.', 'Never log credentials, tokens or personal data.'],
    url: 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/',
  },
  {
    id: 'A10:2021',
    name: 'Server-Side Request Forgery (SSRF)',
    summary: 'The server fetches a URL supplied by the user, letting attackers reach internal services.',
    prevention: [
      'Validate and allow-list destination hosts and schemes.',
      'Block requests to private / link-local address ranges (169.254.169.254, 10.0.0.0/8, ...).',
    ],
    url: 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/',
  },
];
