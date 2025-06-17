
import { verifyToken } from '@clerk/clerk-sdk-node';
import { Context } from 'koa';

const clerkAuthMiddleware = (config: any, { strapi }: { strapi: any }) => {
  return async (ctx: Context, next: () => Promise<any>) => {
    const authHeader = ctx.request.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      ctx.unauthorized('Missing token');
      return;
    }

    const token = authHeader.split(' ')[1];

    try {
       const payload = await verifyToken(token, {
  audience: 'https://huge-owl-18.clerk.accounts.dev',
  issuer: 'https://huge-owl-18.clerk.accounts.dev/.well-known/jwks.json',
});

      ctx.state.user = payload;
      await next();
    } catch (error) {
      strapi.log.error('Clerk token verification failed', error);
      ctx.unauthorized('Invalid Clerk token');
    }
  };
};

export default clerkAuthMiddleware;
