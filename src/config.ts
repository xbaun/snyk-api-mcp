import { z } from 'zod';

function validate<T>(schema: z.ZodSchema<T>, input: unknown): T {
  const result = schema.safeParse(input);
  if (!result.success) {
    throw new Error(
      `Config validation failed:\n${result.error.issues.map((e) => `  ${e.path.join('.')}: ${e.message}`).join('\n')}`,
    );
  }
  return result.data;
}

export const env = validate(
  z.object({
    SNYK_TOKEN: z.string().min(1, 'SNYK_TOKEN is required'),
    SNYK_API_BASE: z.url().default('https://api.eu.snyk.io'),
    SNYK_API_VERSION: z.string().default('2026-03-25'),
  }),
  process.env,
);
