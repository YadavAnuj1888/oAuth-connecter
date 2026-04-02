import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';

export interface JwtPayload {
  sub:       string;
  accountId: string;
  email?:    string;
  iat:       number;
  exp:       number;
}

@Injectable()
export class JwtAuthGuard implements CanActivate {
  canActivate(ctx: ExecutionContext): boolean {
    const req    = ctx.switchToHttp().getRequest();
    const header = req.headers['authorization'] || '';
    const token  = header.startsWith('Bearer ') ? header.slice(7) : null;

    if (!token) throw new UnauthorizedException('Missing Authorization header.');

    try {
      const secret  = process.env.JWT_SECRET;
      if (!secret) throw new Error('JWT_SECRET not set');
      const payload = jwt.verify(token, secret) as JwtPayload;
      req.accountId = payload.accountId || payload.sub;
      req.user      = payload;
      return true;
    } catch {
      throw new UnauthorizedException('Invalid or expired JWT token.');
    }
  }
}
