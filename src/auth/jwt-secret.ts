/**
 * Resolves the JWT signing secret.
 *
 * Fails fast when NODE_ENV=production and JWT_SECRET is missing, so a
 * misconfigured production deployment can never sign tokens with a
 * well-known fallback key. Outside production a clearly-marked insecure
 * dev secret keeps `npm run start:dev` working without extra setup.
 */
export function getJwtSecret(): string {
  const secret = process.env.JWT_SECRET;
  if (secret) return secret;

  if (process.env.NODE_ENV === 'production') {
    throw new Error(
      'JWT_SECRET environment variable is required when NODE_ENV=production',
    );
  }

  return 'dev-only-insecure-jwt-secret';
}
