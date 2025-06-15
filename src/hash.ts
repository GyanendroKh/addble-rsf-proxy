// import { createHash } from 'blake2';
// import nacl from 'tweetnacl';
import sodium from 'libsodium-wrappers';
import { z } from 'zod/v4';

function createOndcSigningString(
  message: string,
  createdAt: number,
  expriesAt: number
) {
  // const digest = createHash('blake2b', {
  //   digestLength: 64
  // })
  //   .update(Buffer.from(message))
  //   .digest('base64');
  const digest = sodium.to_base64(
    sodium.crypto_generichash(64, sodium.from_string(message)),
    sodium.base64_variants.ORIGINAL
  );

  const parts = [
    `(created): ${createdAt}`,
    `(expires): ${expriesAt}`,
    `digest: BLAKE-512=${digest}`
  ];

  return parts.join('\n');
}

function signOndcMessage(message: string, privateKey: string) {
  // const signed = nacl.sign.detached(message, privateKey);
  // return Buffer.from(signed).toString('base64');

  const signed = sodium.crypto_sign_detached(
    message,
    sodium.from_base64(privateKey, sodium.base64_variants.ORIGINAL)
  );

  return sodium.to_base64(signed, sodium.base64_variants.ORIGINAL);
}

export function createOndcSignature(opts: {
  message: string;
  createdAt: number;
  expiresAt: number;
  privateKey: string;
  subId: string;
  keyId: string;
}) {
  const signingString = createOndcSigningString(
    opts.message,
    opts.createdAt,
    opts.expiresAt
  );

  const signature = signOndcMessage(signingString, opts.privateKey);

  const parts = [
    `keyId="${opts.subId}|${opts.keyId}|ed25519"`,
    `algorithm="ed25519"`,
    `created="${opts.createdAt}"`,
    `expires="${opts.expiresAt}"`,
    'headers="(created) (expires) digest"',
    `signature="${signature}"`
  ];

  return `Signature ${parts.join(',')}`;
}

export function extractHeaderParts(
  s: string
): z.infer<typeof headerPartsSchema> | null {
  const regex = /([\w\d]+)="([\w\d\s:.\-/|()=+]+)"/g;

  const parts: Record<string, string> = {};

  let match: RegExpExecArray | null = null;

  while ((match = regex.exec(s)) !== null) {
    if (match[1] && match[2]) {
      parts[match[1]] = match[2];
    }
  }

  const parsed = headerPartsSchema.safeParse(parts);
  if (!parsed.success) {
    return null;
  }

  return parsed.data;
}

export async function verifyOndcSignature(
  parts: z.infer<typeof headerPartsSchema>,
  rawBody: string,
  getPublicKey: (subId: string, keyId: string) => Promise<string | null>
) {
  const [subId, keyId] = parts.keyId.split('|');

  if (!subId || !keyId) {
    return false;
  }

  const publicKey = await getPublicKey(subId, keyId);

  if (!publicKey) {
    return false;
  }

  const signingString = createOndcSigningString(
    rawBody,
    parts.created,
    parts.expires
  );

  // const verified = nacl.sign.detached.verify(
  //   Buffer.from(signingString),
  //   Buffer.from(parts.signature, 'utf8'),
  //   Buffer.from(publicKey, 'base64')
  // );

  const verified = sodium.crypto_sign_verify_detached(
    sodium.from_base64(parts.signature, sodium.base64_variants.ORIGINAL),
    sodium.from_string(signingString),
    sodium.from_base64(publicKey, sodium.base64_variants.ORIGINAL)
  );

  return verified;
}

const headerPartsSchema = z.object({
  keyId: z.string(),
  algorithm: z.string(),
  created: z.coerce.number(),
  expires: z.coerce.number(),
  headers: z.string(),
  signature: z.string()
});
