import express from 'express';
import sodium from 'libsodium-wrappers';

import { env } from './env.js';
import { createOndcSignature } from './hash.js';
import { createProxy } from './proxy.js';

const app = express();

sodium.ready.catch(console.error);

console.log(env.ONDC_PRIVATE_KEY);

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
        keyId: env.ONDC_UKID,
        privateKey: env.ONDC_PRIVATE_KEY,
        subId: env.SUBSCRIBER_ID
      });
    }
  })
);

app.listen(env.PORT, err => {
  if (err) {
    console.error('Failed to start server.', err);
    process.exit(1);
  }

  console.log('Listening on :' + env.PORT);
});
