import { config } from 'dotenv';
import { z } from 'zod';

config({ path: ['.env', '../../.env'], quiet: true });

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  DATABASE_URL: z.string().min(1),
  SESSION_SECRET: z.string().min(32),
  SESSION_TTL_DAYS: z.coerce.number().int().min(1).max(365).default(30),
  COOKIE_SECURE: z
    .string()
    .optional()
    .transform((value) => value === 'true'),
  WEB_ORIGIN: z.string().url().default('http://localhost:5173'),
  EXPORT_MAX_ROWS: z.coerce.number().int().min(1).max(1_000_000).default(100_000),
  AUTH_FAILURE_MAX: z.coerce.number().int().min(1).max(100).default(5),
  AUTH_FAILURE_WINDOW_MINUTES: z.coerce.number().int().min(1).max(24 * 60).default(15),
  AUTH_LOCK_MINUTES: z.coerce.number().int().min(1).max(24 * 60).default(15)
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  console.error('Invalid environment configuration', parsed.error.flatten().fieldErrors);
  throw new Error('Invalid environment configuration');
}

export const env = parsed.data;
