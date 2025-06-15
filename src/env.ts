import 'dotenv/config';

import { createEnv } from '@t3-oss/env-core';
import { z } from 'zod';

export const env = createEnv({
  server: {
    PORT: z.coerce.number().default(4000),

    RSF_URL: z.string().url(),

    SUBSCRIBER_ID: z.string(),
    SUBSCRIBER_URI: z.string().url(),

    KEY_ID: z.string(),
    KEY_SECRET: z.string()
  },
  runtimeEnv: process.env,
  emptyStringAsUndefined: true
});
