/**
 * State Provider Adapter
 * 
 * Adapts the operator node's state to the StateProvider interface
 * required by the EventValidator.
 */

import { StateProvider } from './event-validator';
import { createHash } from 'crypto';

export interface OperatorNodeState {
  accounts: Map<string, any>;
  items: Map<string, any>;
  operators: Map<string, any>;
  settlements: Map<string, any>;
  consignments: Map<string, any>;
  offers?: Map<string, any>;
  operatorCandidates?: Map<string, any>;
}

export class StateProviderAdapter implements StateProvider {
  private state: OperatorNodeState;

  constructor(state: OperatorNodeState) {
    this.state = state;
  }

  updateState(state: OperatorNodeState): void {
    this.state = state;
  }

  getAccount(accountId: string): any | undefined {
    return this.state.accounts.get(accountId);
  }

  getItem(itemId: string): any | undefined {
    return this.state.items.get(itemId);
  }

  getOffer(offerId: string): any | undefined {
    return this.state.offers?.get(offerId);
  }

  getOperator(operatorId: string): any | undefined {
    return this.state.operators.get(operatorId);
  }

  getOperatorCandidate(candidateId: string): any | undefined {
    // Operator candidates are stored in the operators map with status 'pending'
    const operator = this.state.operators.get(candidateId);
    if (operator && operator.status === 'pending') {
      return operator;
    }
    return this.state.operatorCandidates?.get(candidateId);
  }

  getConsignment(consignmentId: string): any | undefined {
    return this.state.consignments.get(consignmentId);
  }

  getSettlement(settlementId: string): any | undefined {
    return this.state.settlements.get(settlementId);
  }

  hasAccountWithAddress(btcAddress: string): boolean {
    for (const account of this.state.accounts.values()) {
      if (account.btcAddress === btcAddress) {
        return true;
      }
    }
    return false;
  }

  hasAccountWithEmail(email: string): boolean {
    // Compute hash for lookup
    const emailHash = createHash('sha256').update(email.toLowerCase().trim()).digest('hex');
    
    for (const account of this.state.accounts.values()) {
      // Check by hash first (new accounts + migrated accounts)
      if (account.emailHash === emailHash) {
        return true;
      }
      // Fallback: check legacy plaintext email for old accounts
      if (account.email && account.email.toLowerCase().trim() === email.toLowerCase().trim()) {
        return true;
      }
    }
    return false;
  }

  getAccountByEmail(email: string): any | undefined {
    // Compute hash for lookup
    const emailHash = createHash('sha256').update(email.toLowerCase().trim()).digest('hex');
    
    for (const account of this.state.accounts.values()) {
      // Check by hash first (new accounts + migrated accounts)
      if (account.emailHash === emailHash) {
        return account;
      }
      // Fallback: check legacy plaintext email for old accounts
      if (account.email && account.email.toLowerCase().trim() === email.toLowerCase().trim()) {
        return account;
      }
    }
    return undefined;
  }

  getActiveOperators(): any[] {
    const active: any[] = [];
    for (const operator of this.state.operators.values()) {
      if (operator.status === 'active') {
        active.push(operator);
      }
    }
    return active;
  }
}
