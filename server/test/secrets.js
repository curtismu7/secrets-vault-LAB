// Credential-shaped test values are assembled at run time, so no such string sits in the repository.
export const SECRETS = {
  github: ['gh', 'p_', 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8'].join(''),
  githubPat: ['github', '_pat_', '11ABCDEFG0abcdefghijkl_mnopqrstuvwxyz0123456789ABCDEFGHIJ'].join(''),
  gitlab: ['glpat', '-', 'AbCdEfGhIjKlMnOpQrSt'].join(''),
  slack: ['xox', 'b-', '123456789012-abcdefghijklmnopqrstuvwx'].join(''),
  aws: ['AKI', 'AIOSFODNN7EXAMPLE'].join(''),
  openai: ['sk', '-proj-', 'Zy9Xw8Vv7Uu6Tt5Ss4Rr3Qq2Pp1'].join(''),
  jwt: ['eyJhbGciOiJIUzI1NiJ9', 'eyJzdWIiOiJhYmNkZWYifQ', 'abcdefghij1234567890XYZ'].join('.'),
  pem: ['-----BEGIN ', 'PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nabcdefghijklmnop\n-----END ', 'PRIVATE KEY-----'].join(''),
  bearer: ['Bear', 'er ', 'abcdEFGH1234567890.tokenvalue'].join(''),
  assignment: ['pass', 'word=', 'hunter2hunter2'].join(''),
  blob: 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5',
  hex: 'deadbeef'.repeat(6),
  // plain-language and short shapes (a review found these raw in a stored reason)
  plainIs: ['my pass', 'word is hunter2xyz'].join(''),
  pwColon: ['p', 'w: Hunter2Secret!'].join(''),
  passEq: ['pa', 'ss=Tr0ub4dor&3'].join(''),
  passphrase: ['pass', 'phrase: correct horse battery'].join(''),
  userinfo: ['https://bob:', 'hunter2@x.example/repo'].join(''),
  tokenWord: ['Authorization: tok', 'en abcdef1234567890zz'].join(''),
  google: ['ya', '29.a0AfH6SMBxQ1w2e3r4t5y6u7i8o9p0'].join(''),
  accountKey: ['Account', 'Key=abcdEFGH', '1234/ijkl'].join(''),
  sessionId: ['session', 'id=00D5g000008dkQz!AQ4AQGhw12'].join(''),
  key31: ['Zq9Xk2Lm8Rt4Vb7N', 'c1Hd5Fj3Gs6Pw0Y'].join(''),
  shortGh: ['gh', 'p_shortone1234'].join(''),
};
// What must NOT be masked: ordinary prose, ids, dates, resource and policy names.
export const PLAIN = [
  'I need read access to review the change for the release',
  'please look at req-0001 on gh-repo-core for maya.chen until 2026-11-02T10:00:00Z under pol-code-write',
  'the token requirements and the password policy are in the handbook',
  'passing the review needs sign-off from priya.nair and lee.park, see non-human-identity-governance-track',
  'Snowflake role ANALYST_RO on main.payments_gold, approved by ines.duarte (a data-owner) in Slack',
  'see https://github.example/payments-api/pull/123 and the incident write-up',
];
