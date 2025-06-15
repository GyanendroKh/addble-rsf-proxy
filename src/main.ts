import express from 'express';

import { env } from './env.js';
import { createProxy } from './proxy.js';

const app = express();

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
