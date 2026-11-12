// Runtime stub for the ESM-only generated Prisma client when running under
// ts-jest (CJS). Only value exports used at runtime need to exist here; all
// other imports from generated/prisma/client are type-only and erased.
export class PrismaClient {
  $connect(): Promise<void> {
    return Promise.resolve();
  }

  $disconnect(): Promise<void> {
    return Promise.resolve();
  }

  $on(): void {
    // no-op
  }
}

export const Prisma = {};
