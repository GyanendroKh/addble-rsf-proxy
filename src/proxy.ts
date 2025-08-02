import { hash } from 'node:crypto';
import { createCache } from 'async-cache-dedupe';
import { Router } from 'express';
import proxy from 'express-http-proxy';
import nacl from 'tweetnacl';

const FROM_ONDC_URL = ['/on_settle', '/on_report', '/recon', '/on_recon'];

const allowedHeaders = [
  'user-agent',
  'content-type',
  'content-length',
  'accept',
  'accept-encoding',
  'accept-language',
  'accept-charset',
  'authorization',
  'host',
  'origin',
  'referer'
];

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
  generateOndcSignature: (
    body: Buffer,
    invalid?: boolean
  ) => string | Promise<string>;
  validateOndcSignature: (
    authorization: string,
    body: Buffer
  ) => Promise<boolean>;
}) {
  const router = Router();

  const cache = createCache({
    ttl: 60 * 10,
    stale: 60 * 10,
    storage: { type: 'memory' }
  }).define('getRsfPublicKey', async function (keyId: string) {
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
  });

  router.post(
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

        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
        (r as any).forwardUrl = url.href.replace(url.origin, '');

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
        proxyReqOptDecorator: async function (r, req) {
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

          let body: Buffer | null = null;
          if (typeof req.body === 'string') {
            body = Buffer.from(req.body, 'utf8');
          } else if (req.body instanceof Buffer) {
            body = req.body;
          } else {
            throw new Error('Invalid Body');
          }

          const invalid = r.headers['x-sig-invalid'] === 'Y';
          const removeSig = r.headers['x-sig-remove'] === 'Y';

          const signatureRes = opts.generateOndcSignature(body, invalid);
          const ondcSignature =
            typeof signatureRes === 'string'
              ? signatureRes
              : await signatureRes;

          if (!removeSig) {
            r.headers['authorization'] = ondcSignature;
          }

          for (const h of Object.keys(r.headers)) {
            if (!allowedHeaders.includes(h)) {
              delete r.headers[h];
            }
          }

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
      proxyReqOptDecorator: async function (r, req) {
        if (!r.headers || isArray(r.headers)) {
          throw new Error('Headers are not an object');
        }

        const authorization = r.headers.authorization;
        if (!authorization) {
          throw new Error('No Authorization header found');
        }

        let body: Buffer | null = null;
        if (typeof req.body === 'string') {
          body = Buffer.from(req.body, 'utf8');
        } else if (req.body instanceof Buffer) {
          body = req.body;
        } else {
          throw new Error('Invalid Body');
        }

        const isValid = await opts.validateOndcSignature(authorization, body);
        if (!isValid) {
          throw new Error('Invalid Signature.');
        }

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
