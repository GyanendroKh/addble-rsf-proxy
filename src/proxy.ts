import { hash } from 'node:crypto';
import { createCache } from 'async-cache-dedupe';
import { Router } from 'express';
import proxy from 'express-http-proxy';
import nacl from 'tweetnacl';

const FROM_ONDC_URL = ['/on_settle', '/on_report', '/on_recon'];

export function createProxy(opts: {
  rsfUrl: string;
  subscriber: {
    id: string;
    uri: string;
  };
  credential: {
    keyId: string;
    secretKey: string;
  };
}) {
  const router = Router();

  const cache = createCache().define(
    'getRsfPublicKey',
    async function (keyId: string) {
      const res = await fetch(new URL('/public/auth/keys', opts.rsfUrl), {
        method: 'GET'
      });

      if (!res.ok) {
        return null;
      }

      const data = (await res.json().catch(err => {
        console.error(err);

        return undefined;
      })) as { keyId: string; publicKey: string }[] | undefined;

      const key = data?.find(i => i.keyId === keyId);
      if (!key) {
        return null;
      }

      return key;
    }
  );

  router.post(
    '/rsf',
    proxy(
      function (r) {
        let forwardUrl = r.header('x-forward-to');
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
        proxyReqPathResolver: function (r) {
          const forwardUrl =
            'forwardUrl' in r && typeof r.forwardUrl === 'string'
              ? r.forwardUrl
              : null;

          if (!forwardUrl) {
            throw new Error('No URL found!');
          }

          return forwardUrl;
        },
        proxyReqOptDecorator: async function (r) {
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

          const key = await cache.getRsfPublicKey(keyId);
          if (!key) {
            throw new Error('Invalid Key Id');
          }

          const msg = nacl.sign.open(
            Buffer.from(signature, 'hex'),
            Buffer.from(key.publicKey, 'base64')
          );

          if (!msg) {
            throw new Error('Invalid Signature');
          }

          const calculated = hash(
            'sha256',
            [opts.subscriber.id, opts.subscriber.uri].join('|'),
            'buffer'
          );

          if (!nacl.verify(msg, calculated)) {
            throw new Error('Invalid Signature');
          }

          delete r.headers['x-forward-to'];
          delete r.headers['x-key-id'];
          delete r.headers['x-signature'];

          return r;
        }
      }
    )
  );

  router.post(
    FROM_ONDC_URL,
    proxy(opts.rsfUrl, {
      filter: r => r.method === 'POST' && FROM_ONDC_URL.includes(r.path),
      proxyReqPathResolver: r => '/api/v1/ondc' + r.url,
      proxyReqOptDecorator: function (r) {
        if (!r.headers || isArray(r.headers)) {
          throw new Error('Headers are not an object');
        }

        const authorization = r.headers.authorization;

        r.headers['x-key-id'] = opts.credential.keyId;
        r.headers['x-secret-key'] = opts.credential.secretKey;

        delete r.headers.authorization;

        return r;
      }
    })
  );

  return router;
}

function isArray(arg: any): arg is readonly any[] {
  return Array.isArray(arg);
}
