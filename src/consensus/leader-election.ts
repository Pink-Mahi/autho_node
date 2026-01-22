/**
 * Leader Election - Automatic failover when main node goes down
 * Uses deterministic selection based on operator IDs to avoid split-brain
 */

export interface OperatorInfo {
  operatorId: string;
  btcAddress: string;
  lastSeen: number;
  isHealthy: boolean;
}

export interface LeaderElectionResult {
  leaderId: string | null;
  isMainNodeAlive: boolean;
  backupLeader: string | null;
  eligibleOperators: string[];
}

export class LeaderElection {
  private static readonly MAIN_NODE_TIMEOUT_MS = 180000; // 3 minutes
  private static readonly OPERATOR_TIMEOUT_MS = 120000; // 2 minutes

  /**
   * Elect a leader from available operators
   * Main node is always preferred if alive
   * Otherwise, use deterministic selection (lowest operatorId)
   */
  static electLeader(
    operators: OperatorInfo[],
    mainNodeLastSeen: number,
    currentTime: number = Date.now()
  ): LeaderElectionResult {
    // Check if main node is alive
    const mainNodeAge = currentTime - mainNodeLastSeen;
    const isMainNodeAlive = mainNodeAge < this.MAIN_NODE_TIMEOUT_MS;

    if (isMainNodeAlive) {
      // Main node is leader
      const backupLeader = this.selectBackupLeader(operators, currentTime);
      return {
        leaderId: 'main-node',
        isMainNodeAlive: true,
        backupLeader,
        eligibleOperators: operators
          .filter(op => this.isOperatorHealthy(op, currentTime))
          .map(op => op.operatorId)
      };
    }

    // Main node is down - elect from operators
    const healthyOperators = operators.filter(op => 
      this.isOperatorHealthy(op, currentTime)
    );

    if (healthyOperators.length === 0) {
      return {
        leaderId: null,
        isMainNodeAlive: false,
        backupLeader: null,
        eligibleOperators: []
      };
    }

    // Deterministic selection: sort by operatorId and pick first
    // This ensures all nodes agree on the same leader
    const sortedOperators = [...healthyOperators].sort((a, b) => 
      a.operatorId.localeCompare(b.operatorId)
    );

    const leader = sortedOperators[0];
    const backup = sortedOperators.length > 1 ? sortedOperators[1] : null;

    return {
      leaderId: leader.operatorId,
      isMainNodeAlive: false,
      backupLeader: backup?.operatorId || null,
      eligibleOperators: sortedOperators.map(op => op.operatorId)
    };
  }

  /**
   * Select backup leader (second in line)
   */
  private static selectBackupLeader(
    operators: OperatorInfo[],
    currentTime: number
  ): string | null {
    const healthyOperators = operators
      .filter(op => this.isOperatorHealthy(op, currentTime))
      .sort((a, b) => a.operatorId.localeCompare(b.operatorId));

    return healthyOperators.length > 0 ? healthyOperators[0].operatorId : null;
  }

  /**
   * Check if operator is healthy (recently seen)
   */
  private static isOperatorHealthy(
    operator: OperatorInfo,
    currentTime: number
  ): boolean {
    const age = currentTime - operator.lastSeen;
    return operator.isHealthy && age < this.OPERATOR_TIMEOUT_MS;
  }

  /**
   * Check if current node should act as leader
   */
  static shouldActAsLeader(
    myOperatorId: string,
    electionResult: LeaderElectionResult
  ): boolean {
    return electionResult.leaderId === myOperatorId;
  }

  /**
   * Check if current node is backup leader
   */
  static isBackupLeader(
    myOperatorId: string,
    electionResult: LeaderElectionResult
  ): boolean {
    return electionResult.backupLeader === myOperatorId;
  }
}
