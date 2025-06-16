import { randomUUID } from 'node:crypto';
import express from 'express';
import sodium from 'libsodium-wrappers';
import { pino } from 'pino';
import { pinoHttp } from 'pino-http';

import { env } from './env.js';
import {
  createOndcSignature,
  extractHeaderParts,
  verifyOndcSignature
} from './hash.js';
import { createProxy } from './proxy.js';

const app = express();
const logger = pino();

app.disable('etag');
app.disable('x-powered-by');

app.use(
  pinoHttp({
    logger: logger,
    genReqId: () => randomUUID(),
    customReceivedMessage: req => {
      return `[${req.method}] ${req.url}`;
    }
  })
);

sodium.ready.catch(console.error);

app.use(
  createProxy({
    rsfUrl: env.RSF_URL,
    subscriber: {
      id: env.SUBSCRIBER_ID,
      uri: env.SUBSCRIBER_URI
    },
    credential: {
      keyId: env.KEY_ID,
      secretKey: env.KEY_SECRET
    },
    generateOndcSignature(body) {
      return createOndcSignature({
        message: body,
        createdAt: Math.floor(Date.now() / 1000),
        expiresAt: Math.floor(Date.now() / 1000 + 60),
        subId: env.SUBSCRIBER_ID,
        keyId: env.ONDC_UKID,
        privateKey: sodium.from_base64(
          env.ONDC_PRIVATE_KEY,
          sodium.base64_variants.ORIGINAL
        )
      });
    },
    validateOndcSignature: async (authorization, body) => {
      const parts = extractHeaderParts(authorization);
      if (!parts) {
        throw new Error('Invalid Authorization header');
      }

      const [subId] = parts.keyId.split('|');

      if (subId === 'sa_nocs.nbbl.com') {
        console.log('skipping validation for sa_nocs.nbbl.com');
        console.log('header parts', parts);
        console.log('signature', authorization);

        return true;
      }

      const isValid = await verifyOndcSignature(
        parts,
        body,
        async function (subId, keyId) {
          const r = await getOndcSubscriberPublicKey(subId, keyId);

          if (!r) {
            return null;
          }

          return Buffer.from(r, 'base64');
        }
      );

      return isValid;
    }
  })
);

const getOndcSubscriberPublicKey = async (subId: string, keyId: string) => {
  const body = JSON.stringify({
    subscriber_id: subId,
    doamin: 'ONDC:NTS10',
    country: 'IN'
  });

  const signature = createOndcSignature({
    message: Buffer.from(body, 'utf8'),
    createdAt: Math.floor(Date.now() / 1000),
    expiresAt: Math.floor(Date.now() / 1000 + 60),
    subId: env.SUBSCRIBER_ID,
    keyId: env.ONDC_UKID,
    privateKey: sodium.from_base64(
      env.ONDC_PRIVATE_KEY,
      sodium.base64_variants.ORIGINAL
    )
  });

  const res = await fetch('https://preprod.registry.ondc.org/v2.0/lookup', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: signature
    },
    body
  });

  if (!res.ok) {
    console.log('lookup', { subId }, res.status, await res.text());
    return null;
  }

  const resBody = (await res.json().catch(err => {
    console.error(err);

    return undefined;
  })) as Array<{ ukId: string; signing_public_key: string }> | undefined;

  const key = resBody?.find(i => i.ukId === keyId);

  if (!key) {
    console.log('lookup no kid', { subId, keyId }, resBody);

    return null;
  }

  return key.signing_public_key;
};

app.listen(env.PORT, err => {
  if (err) {
    logger.error(err, 'Failed to start server.');
    process.exit(1);
  }

  logger.info('Server started on :%d', env.PORT);
});
