import { Module }          from '@nestjs/common';
import { TypeOrmModule }   from '@nestjs/typeorm';
import { IntegrationEntity }     from './entities/integration.entity';
import { IntegrationsController, CallerdeskController, AuthController } from './controllers/integrations.controller';
import { OAuthService }          from './services/oauth.service';
import { TokenService }          from './services/token.service';
import { CredentialService }     from './services/credential.service';
import { TokenRefreshQueue }     from './queues/token-refresh.queue';
import { TokenRefreshProcessor } from './queues/token-refresh.processor';
import { RedisOAuthStateStore }  from './store/redis-oauth-state.store';
import { EncryptionService }     from '../../common/crypto/encryption.service';
import { JwtAuthGuard }          from '../../common/guards/jwt-auth.guard';

@Module({
  imports: [TypeOrmModule.forFeature([IntegrationEntity])],
  controllers: [IntegrationsController, CallerdeskController, AuthController],
  providers: [
    EncryptionService,
    JwtAuthGuard,
    RedisOAuthStateStore,
    OAuthService,
    TokenService,
    CredentialService,
    TokenRefreshQueue,
    TokenRefreshProcessor,
  ],
  exports: [OAuthService, TokenService, EncryptionService],
})
export class IntegrationsModule {
  constructor(
    private readonly processor: TokenRefreshProcessor,
    private readonly tokenSvc:  TokenService,
  ) {
    this.processor.setTokenService(this.tokenSvc);
  }
}
