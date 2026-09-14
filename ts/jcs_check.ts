// RFC 8785 (JCS) cross-implementation check for the CLC-1.6 canonicalization
// (rev CLC-1.6).  Pins the review reproducer: Go's json.Marshal HTML-escaped
// `&` to `\u0026`, so the material-projection digest and `clc-action:`
// identifier were not RFC 8785.  Asserts the JCS bytes, the SHA-256 digest, the
// clc-action identifier and the UTF-16 key ordering.
//
// Run: node --experimental-strip-types ts/jcs_check.ts
import { createHash } from 'node:crypto';
import { canonicalJSON, computeActionId } from './clc_semantics.ts';

const EXPECT_BYTES = '{"value":"&"}';
const EXPECT_SHA256 = '9a2fe282f2733070b5a91a182e97d8efdf6e94135e4790a73a380257200a2903';
const EXPECT_B64URL = 'mi_igvJzMHC1qRoYLpfY799ulBNeR5CnOjgCVyAKKQM';
const EXPECT_ID = 'clc-action:1:probe.action.1:jcs-sha256:' + EXPECT_B64URL;

// UTF-16 order: "a" (0x61) < U+1F4A9 (surrogate 0xD83D) < U+E000.  A UTF-8 byte
// sort would put U+E000 (EE 80 80) before U+1F4A9 (F0 9F 92 A9).
const EXPECT_KEY_ORDER = '{"a":"ascii","\u{1F4A9}":"astral","\uE000":"bmp"}';

const fails: string[] = [];
function check(label: string, got: string, want: string): void {
    if (got !== want) fails.push(`${label}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
}

const bytesOut = canonicalJSON({ value: '&' });
check('JCS bytes', bytesOut, EXPECT_BYTES);
check('sha256', createHash('sha256').update(bytesOut, 'utf8').digest('hex'), EXPECT_SHA256);
check('b64url', createHash('sha256').update(bytesOut, 'utf8').digest('base64url'), EXPECT_B64URL);
check('action id', computeActionId('probe.action.1', ['value'], 'jcs-sha256', { value: '&' }), EXPECT_ID);
check('utf-16 key order', canonicalJSON({ '\uE000': 'bmp', '\u{1F4A9}': 'astral', a: 'ascii' }), EXPECT_KEY_ORDER);

// Invalid Unicode is refused, not repaired or escaped: a lone surrogate has no
// UTF-8 form and therefore no JCS encoding (RFC 8785 3.2.2.2).  A well-formed
// pair is accepted and stays raw.
check('surrogate pair accepted', canonicalJSON('\u{1F602}'), '"\u{1F602}"');
for (const [label, input] of [
    ['lone high surrogate', '\ud800'],
    ['lone low surrogate', '\udc00'],
    ['lone surrogate key', { ['\ud800']: 1 }],
] as [string, unknown][]) {
    let refused = false;
    try {
        canonicalJSON(input);
    } catch {
        refused = true;
    }
    check(label + ' refused', String(refused), 'true');
}

if (fails.length > 0) {
    console.error(fails.join('\n'));
    process.exit(1);
}
console.log('jcs_check: 9 checks passed (RFC 8785 bytes/digest/action-id/key-order/invalid-unicode)');
