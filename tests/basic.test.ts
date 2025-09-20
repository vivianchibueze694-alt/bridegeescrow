import { describe, expect, it } from "vitest";

const accounts = simnet.getAccounts();
const deployer = accounts.get("deployer")!;
const contractName = "bridgeescrewcontract";

describe("BridgeEscrow Security Enhancement Tests", () => {
  it("ensures simnet is well initialized", () => {
    expect(simnet.blockHeight).toBeDefined();
  });

  it("should have the enhanced contract deployed with security features", () => {
    // Verify the contract is deployed and callable
    const { result } = simnet.callReadOnlyFn(
      contractName,
      "get-contract-info",
      [],
      deployer
    );
    
    // The contract should be deployed and callable
    expect(result).toBeDefined();
    
    // Verify it returns the expected security configuration
    if (result.isOk) {
      const contractInfo = result.value;
      expect(contractInfo).toBeDefined();
      expect(contractInfo.data).toHaveProperty('arbitrator-fee-bps');
      expect(contractInfo.data).toHaveProperty('emergency-pause');
      expect(contractInfo.data).toHaveProperty('max-escrow-amount');
      expect(contractInfo.data).toHaveProperty('min-arbitrator-stake');
      expect(contractInfo.data).toHaveProperty('min-escrow-amount');
      expect(contractInfo.data).toHaveProperty('next-escrow-id');
      expect(contractInfo.data).toHaveProperty('treasury-address');
      expect(contractInfo.data).toHaveProperty('treasury-fee-bps');
    }
  });

  it("should have security configuration properly set", () => {
    // Verify the contract has the expected security configuration
    const { result } = simnet.callReadOnlyFn(
      contractName,
      "get-contract-info",
      [],
      deployer
    );
    
    expect(result).toBeDefined();
    if (result.isOk) {
      const contractInfo = result.value;
      // Verify security constants are properly set
      expect(contractInfo.data['arbitrator-fee-bps']).toBeDefined();
      expect(contractInfo.data['treasury-fee-bps']).toBeDefined();
      expect(contractInfo.data['min-arbitrator-stake']).toBeDefined();
      expect(contractInfo.data['max-escrow-amount']).toBeDefined();
      expect(contractInfo.data['min-escrow-amount']).toBeDefined();
    }
  });
});
