import sodium from 'libsodium-wrappers';
import { z } from 'zod/v4';

function createOndcSigningString(
  message: Uint8Array,
  createdAt: number,
  expriesAt: number
) {
  const digest = sodium.to_base64(
    sodium.crypto_generichash(64, message),
    sodium.base64_variants.ORIGINAL
  );

  const parts = [
    `(created): ${createdAt}`,
    `(expires): ${expriesAt}`,
    `digest: BLAKE-512=${digest}`
  ];

  return parts.join('\n');
}

function signOndcMessage(message: string, privateKey: Uint8Array) {
  const signed = sodium.to_base64(
    sodium.crypto_sign_detached(message, privateKey),
    sodium.base64_variants.ORIGINAL
  );

  return signed;
}

export function createOndcSignature(opts: {
  message: Uint8Array;
  createdAt: number;
  expiresAt: number;
  privateKey: Uint8Array;
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
  rawBody: Uint8Array,
  getPublicKey: (subId: string, keyId: string) => Promise<Uint8Array | null>
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

  const verified = sodium.crypto_sign_verify_detached(
    sodium.from_base64(parts.signature, sodium.base64_variants.ORIGINAL),
    sodium.from_string(signingString),
    publicKey
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
