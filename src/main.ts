import { hash } from 'node:crypto';
import { createCache } from 'async-cache-dedupe';
import express from 'express';
import proxy from 'express-http-proxy';
import nacl from 'tweetnacl';

import { env } from './env.js';

const app = express();

const FROM_ONDC = ['/on_settle', '/on_report', '/on_recon'];
const RSF_URL = env.RSF_URL;

const SUBSCRIBER_ID = env.SUBSCRIBER_ID;
const SUBSCRIBER_URI = env.SUBSCRIBER_URI;

const KEY_ID = env.KEY_ID;
const KEY_SECRET = env.KEY_SECRET;

function isArray(arg: any): arg is readonly any[] {
  return Array.isArray(arg);
}

const cache = createCache().define('getPublicKey', async keyId => {
  const res = await fetch(new URL('/public/auth/keys', RSF_URL), {
    method: 'GET'
  });

  if (!res.ok) {
    return null;
  }

  const body = (await res.json()) as
    | { keyId: string; publicKey: string }[]
    | undefined;

  const key = body?.find(i => i.keyId === keyId);
  if (!key) {
    return null;
  }

  return key;
});

app.post(
  '/rsf',
  proxy(
    function (r) {
      let forwardUrl = r.headers['x-forward-to'];
      if (Array.isArray(forwardUrl)) {
        forwardUrl = forwardUrl[0];
      }
      if (!forwardUrl) {
        throw new Error('No forward URL found!');
      }

      const url = new URL(forwardUrl);

      // @ts-expect-error No type for this
      r.forwardUrl = url.href.replace(url.origin, '');

      return url.origin;
    },
    {
      proxyReqPathResolver: r => {
        const forwardUrl =
          'forwardUrl' in r && typeof r.forwardUrl === 'string'
            ? r.forwardUrl
            : null;

        if (!forwardUrl) {
          throw new Error('No URL found!');
        }

        return forwardUrl;
      },
      proxyReqOptDecorator: async (r, _r) => {
        if (!r.headers || isArray(r.headers)) {
          throw new Error('Headers are not an object');
        }

        let keyId = r.headers['x-key-id'];
        let signature = r.headers['x-signature'];

        if (Array.isArray(keyId)) {
          keyId = keyId[0];
        }
        if (Array.isArray(signature)) {
          signature = signature[0];
        }

        if (typeof keyId !== 'string' || typeof signature !== 'string') {
          throw new Error('Invalid Key Id or Signature');
        }

        console.log({ keyId, signature });

        const key = await cache.getPublicKey(keyId);
        if (!key) {
          throw new Error('Invalid Key Id');
        }

        const a = nacl.sign.open(
          Buffer.from(signature, 'hex'),
          Buffer.from(key.publicKey, 'base64')
        );

        if (!a) {
          throw new Error('Invalid Signature');
        }

        const msg = Buffer.from(a).toString('hex');
        const calculated = hash(
          'sha256',
          [SUBSCRIBER_ID, SUBSCRIBER_URI].join('|'),
          'hex'
        );

        if (msg !== calculated) {
          throw new Error('Invalid Signature');
        }

        delete r.headers['x-forward-to'];
        delete r.headers['x-key-id'];
        delete r.headers['x-signature'];

        console.log({ body: _r.body.toString() });

        return r;
      }
    }
  )
);

app.post(
  FROM_ONDC,
  proxy(env.RSF_URL, {
    filter: r => {
      console.log('GOT_REQUEST', r.url);

      const url = new URL(r.url, 'http://localhost');

      return r.method === 'POST' && FROM_ONDC.includes(url.pathname);
    },
    proxyReqPathResolver: r => {
      return '/api/v1/ondc' + r.url;
    },
    proxyReqOptDecorator: r => {
      if (!r.headers || isArray(r.headers)) {
        throw new Error('Headers are not an object');
      }

      const authorization = r.headers.authorization;

      r.headers['x-key-id'] = KEY_ID;
      r.headers['x-secret-key'] = KEY_SECRET;

      delete r.headers['authorization'];

      return r;
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
