import { VerifyResult } from '../interfaces/crm-adapter.interface';

export interface ICrmVerifier {
  verify(body: Record<string, any>): Promise<VerifyResult>;
}

const registry = new Map<string, ICrmVerifier>();

export function CrmVerifier(provider: string): ClassDecorator {
  return (target: any) => {
    registry.set(provider, new target());
  };
}

export function getVerifier(provider: string): ICrmVerifier | undefined {
  return registry.get(provider);
}
