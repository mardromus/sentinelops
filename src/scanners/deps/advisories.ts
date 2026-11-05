/**
 * Offline advisory snapshot.
 *
 * A small, hand-checked subset of well-known advisories so that scans work
 * in air-gapped CI and in tests. With network access SentinelOps queries
 * OSV.dev instead, which covers the full GitHub Advisory / PyPA databases.
 */
import { Severity } from '../../common/types';
import { Range } from './version';

export interface Advisory {
  id: string;
  aliases: string[];
  ecosystem: 'npm' | 'PyPI';
  package: string;
  ranges: Range[];
  severity: Severity;
  summary: string;
  cwe: string[];
  references: string[];
}

const nvd = (cve: string) => `https://nvd.nist.gov/vuln/detail/${cve}`;
const A = (
  cve: string,
  ecosystem: 'npm' | 'PyPI',
  pkg: string,
  ranges: Range[],
  severity: Severity,
  summary: string,
  cwe: string[],
): Advisory => ({
  id: cve,
  aliases: [cve],
  ecosystem,
  package: pkg,
  ranges,
  severity,
  summary,
  cwe,
  references: [nvd(cve), `https://osv.dev/list?q=${cve}`],
});

export const OFFLINE_ADVISORIES: Advisory[] = [
  A('CVE-2021-23337', 'npm', 'lodash', [{ fixed: '4.17.21' }], 'high', 'Command injection via the template function', ['CWE-94']),
  A('CVE-2020-8203', 'npm', 'lodash', [{ fixed: '4.17.19' }], 'high', 'Prototype pollution in zipObjectDeep', ['CWE-1321']),
  A('CVE-2021-44906', 'npm', 'minimist', [{ fixed: '0.2.4' }, { introduced: '1.0.0', fixed: '1.2.6' }], 'critical', 'Prototype pollution', [
    'CWE-1321',
  ]),
  A(
    'CVE-2022-23540',
    'npm',
    'jsonwebtoken',
    [{ fixed: '9.0.0' }],
    'high',
    'Signature validation bypass through insecure default algorithm in jwt.verify',
    ['CWE-347'],
  ),
  A('CVE-2020-28168', 'npm', 'axios', [{ fixed: '0.21.1' }], 'medium', 'Server-side request forgery via redirects to private addresses', [
    'CWE-918',
  ]),
  A('CVE-2021-3749', 'npm', 'axios', [{ fixed: '0.21.2' }], 'high', 'Regular expression denial of service in trim', ['CWE-1333']),
  A(
    'CVE-2022-0235',
    'npm',
    'node-fetch',
    [{ fixed: '2.6.7' }, { introduced: '3.0.0', fixed: '3.1.1' }],
    'high',
    'Cookie and authorization headers forwarded to third-party hosts on redirect',
    ['CWE-200'],
  ),
  A(
    'CVE-2024-29041',
    'npm',
    'express',
    [{ fixed: '4.19.2' }],
    'medium',
    'Open redirect via malformed URLs in res.location / res.redirect',
    ['CWE-601'],
  ),
  A('CVE-2022-31129', 'npm', 'moment', [{ introduced: '2.18.0', fixed: '2.29.4' }], 'high', 'Inefficient RFC2822 parsing leads to ReDoS', [
    'CWE-1333',
  ]),
  A(
    'CVE-2021-32640',
    'npm',
    'ws',
    [
      { introduced: '5.0.0', fixed: '5.2.3' },
      { introduced: '6.0.0', fixed: '6.2.2' },
      { introduced: '7.0.0', fixed: '7.4.6' },
    ],
    'medium',
    'ReDoS in Sec-Websocket-Protocol header parsing',
    ['CWE-1333'],
  ),
  A('CVE-2021-23369', 'npm', 'handlebars', [{ fixed: '4.7.7' }], 'critical', 'Remote code execution when compiling untrusted templates', [
    'CWE-94',
  ]),
  A(
    'CVE-2023-32681',
    'PyPI',
    'requests',
    [{ introduced: '2.3.0', fixed: '2.31.0' }],
    'medium',
    'Proxy-Authorization header leaked to destination on HTTPS redirect',
    ['CWE-200'],
  ),
  A('CVE-2020-14343', 'PyPI', 'pyyaml', [{ fixed: '5.4' }], 'critical', 'Arbitrary code execution through full_load / FullLoader', [
    'CWE-20',
  ]),
  A('CVE-2021-33503', 'PyPI', 'urllib3', [{ introduced: '1.25.4', fixed: '1.26.5' }], 'high', 'ReDoS in URL authority parsing', [
    'CWE-1333',
  ]),
  A('CVE-2020-28493', 'PyPI', 'jinja2', [{ fixed: '2.11.3' }], 'medium', 'ReDoS in the urlize filter', ['CWE-1333']),
  A(
    'CVE-2023-30861',
    'PyPI',
    'flask',
    [{ fixed: '2.2.5' }, { introduced: '2.3.0', fixed: '2.3.2' }],
    'high',
    'Session cookie may be cached by proxies and shared between clients',
    ['CWE-539'],
  ),
];
