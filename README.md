## Full EIP-1884 contract-library.com analysis

![gas is too damn high](https://opimedia.azureedge.net/-/media/Images/MEN/Editorial/Blogs/Ask-Our-Experts/Why-Is-Gas-Suddenly-So-Expensive/gas-prices1.gif?la=en&hash=78FE781F98614F6BC2135F56B4C5D85165DD32E5 "gas is too damn high :)")

Contact @neville_grech on Twitter, @dedaub on Telegram in case of questions or comments

## [Background](https://github.com/holiman/eip-1884-security/blob/master/README.md#background)

[EIP 1884](https://eips.ethereum.org/EIPS/eip-1884) is set to be implemented into the upcoming Ethereum 'Istanbul' hard fork. It:

- increases the cost of opcode `SLOAD` from `200` to `800` gas
- increases the cost of `BALANCE` and `EXTCODEHASH` from `400` to `700` gas
- adds a new opcode `SELFBALANCE` with cost `5`.

Due to a fixed gas limit imposed by the `.send(..)` and `.transfer(..)` Solidity functions, fallback functions that
use these opcodes may now start to fail due to an out-of-gas exception.

## Analysis by Contract-library.com team
Contract-library.com, an automated security service, performs sophisticated static analysis on all deployed smart contracts (over 20 million of them). As static analysis is a technique to find all possible program executions, if correctly implemented, it is bound to find the most comprehensive list of smart contracts affected by security vulnerabilities.

On Friday August 16th Martin Holst Swende from the Ethereum foundation asked a question on the ETHSecurity channel on telegram about how to go about finding smart contracts that may fail the fallback function due to the EIP-1884. Since contract-library.com already had gas consumption analysis built into its core static analyses so we reached out with a [list of contracts](https://contract-library.com/?w=FALLBACK_WILL_FAIL) (constantly updated) that may be affected that same day.


Over the subsequent days, also with the input of Martin Holst Swende, the gas cost analysis computation was updated and many of its deficencies fixed. The analysis currently reveals over 800 contracts that are highly likely to fail if called with 2300 gas (whereas they would succeed prior to EIP-1884). [A subsequent, sounder, analysis](https://contract-library.com/?w=FALLBACK_MAY_FAIL) was also developed. This would be the most comprehensive list of affected smart contracts for this particular issue, but also contains many false positives. This sounder "may" analysis revealed that 7000 currently deployed smart contracts may fail under some execution paths with 2300 gas.

In addition, since our analysis is fully automated, we have also performed experiments to see whether these issues can be simply avoided by repricing the `LOG0, LOG1 ...` opcodes. Note that these opcodes tend to happen quite often in fallback functions. By halving the `Glog` and `Glogtopic` gas costs (refer to [yellow paper](https://ethereum.github.io/yellowpaper/paper.pdf)), [the number of flagged contracts is reduced by approximately half](https://contract-library.com/?w=FALLBACK_WILL_FAIL%20(cheap%20LOG))!

Although repricing opcodes can always break contracts, the EVM should be able to evolve too. Clearly, a decent number of
contracts will be broken due to this change, so care must be taken to lessen the impact on the overall ecosystem.
In this case, we recommend repricing the `LOGx` opcodes, which seem to be mispriced anyway. This way, there will be
fewer contracts affected.

A more interesting, but *perhaps equally serious side-effect* of EIP-1884 and EIP-2200 *combined* is that it lowers the cost of an attacker to perform an *unbounded mass iteration* attack, which is currently quite high. This attack is described in [MadMax](https://www.nevillegrech.com/assets/pdf/madmax-oopsla18.pdf). In summary, this is an attack carried out by an unauthorized user, to increase the size of an array or data structure, that is iterated upon by any other user, rendering the functionality inaccessible by increasing gas cost beyond the block gas limit. The *combined* effect of EIP-1884 and EIP-2200 make this kind of attack around 7 times cheaper on average, rendering it much more feasible. This attack requires 2 SSTOREs per array element that is added by the attacker. This array is then iterated upon by the victim, requiring an additional SLOAD. For a list of contracts that may be susceptable to unbounded iteration, [we have you covered](https://contract-library.com/?w=DoS%20(Unbounded%20Operation)). The list contains approximately 15k contracts.

## Which contracts will be affacted? What about the one I'm currently developing?
If your contract does not [have fallbacks which may fail with 2300 gas](https://contract-library.com/?w=FALLBACK_MAY_FAIL)) or is not [susceptable to unbounded iteration](https://contract-library.com/?w=DoS%20(Unbounded%20Operation)), then you're most probably fine. If it is, you may still be ok, but further investigation is necessary. If you would like to see whether the contract you are developing may be affected, deploy it to one of the Ethereum testnets and check your results at contract-library.com.

#### [KyberNetwork](https://contract-library.com/contracts/Ethereum/0x9ae49c0d7f8f9ef4b864e004fe86ac8294e20950)
```js
    function() public payable {
        require(reserveType[msg.sender] != ReserveType.NONE);
        EtherReceival(msg.sender, msg.value);
    }
```
#### [NEXXO crowdsale](https://contract-library.com/contracts/Ethereum/0x2c7fa71e31c0c6bb9f21fc3c098ac2c53f8598cc) :

```

    modifier onlyICO() {
        require(now >= icoStartDate && now < icoEndDate, "CrowdSale is not running");
        _;
    }

    function () public payable onlyICO{
        require(!stopped, "CrowdSale is stopping");
    }

```
For NEXXO, it checks three slots, `icoStartDate`, `icoEndDate` and `stopped`, totalling `2400` with new gas rules. 


#### [Crowd Machine Compute Token crowdsale](https://contract-library.com/contracts/Ethereum/0x5fe56cb82b3d88b6e37d3a9dba8f5b40b28dda7e):
```
  modifier onlyIfRunning
  {
    require(running);
    _;
  }

  function () public onlyIfRunning payable {
    require(isApproved(msg.sender));
    LogEthReceived(msg.sender, msg.value);
  }

```
Important reminder: The crowdsales above do not inherently _break_, it just means that callers need to add some more gas than `2300` to partake in the ICO contracts. 


#### [CappedVault](https://contract-library.com/contracts/Ethereum/0x91b9d2835ad914bc1dcfe09bd1816febd04fd689)
- Fallback function:
```js
    function () public payable {
        require(total() + msg.value <= limit);
    }
```
#### [Unknown Harvester with 5 ETH](https://contract-library.com/contracts/Ethereum/0x1347bb1cef4bf0db92294c1b52a22f190eaa04ac)
```js
  require((msg.value >= stor___function_selector__));
  emit 0xafd096c64445a293507447c2ecb78f03b4f5459ec28b8e9bfe113c35b75d624a(address(msg.sender), msg.value, 0x447);
  exit();
```
No source code available. Note that this contract would work if `LOGx` gas cost is reduced.

#### [Aragon's DepositableDelegateProxy](https://contract-library.com/contracts/Ethereum/0x0a74d136fafed0f8d58ce4b7307283695ec7a0b6)
```js
    function isDepositable() public view returns (bool) {
        return DEPOSITABLE_POSITION.getStorageBool();
    }

    event ProxyDeposit(address sender, uint256 value);

    function () external payable {
        // send / transfer
        if (gasleft() < FWD_GAS_LIMIT) {
            require(msg.value > 0 && msg.data.length == 0);
            require(isDepositable());
            emit ProxyDeposit(msg.sender, msg.value);
        } else { // all calls except for send or transfer
            address target = implementation();
            delegatedFwd(target, msg.data);
        }
    }
}
```
Note that this contract would work if `LOGx` gas cost is reduced. According to the contract library analysis, the fallback function may fail due to anywhere between 2308 and 2438 gas. [Issue at Aragon](https://github.com/aragon/aragonOS/issues/549)

## How does the static analysis on contract-library.com work?

Static program analysis is a technique that considers all program's behaviors without having to execute the program. Static analysis is generally thought to be expensive, but over the years we have developed techniques to counter this. Firstly, we developed new techniques in the area of "declarative program analysis", which simplifies implementations and make these analysis simpler. Secondly, we have applied our analysis at scale, which makes them worth the effort. Contract-library's internal analysis framework decompiles all smart contracts on the main Ethereum network and testnets to an IR representation, ameanable to analysis. The decompilation framework is described in our [ICSE 2019 paper](https://www.nevillegrech.com/assets/pdf/gigahorse-icse.pdf). Following this analysis, many "client analysis", are applied. These analyses all benefit from a rich suite of analysis primitives, such as gas cost analysis (similar to worst-case execution analysis), memory contents analysis, etc. that are instantiated and customized in each client analysis. Finally, we encode all our analysis, decompilers, etc. in a declarative language, and automatically synthesize a fast C++ implementation using [Soufflé](https://souffle-lang.github.io/).

The `FALLBACK_WILL_FAIL` static analysis is encoded in the following *simplified* datalog spec, deployed on contract-library.com:

```prolog
% Restrict the edges that form the possible paths to those in fallback functions
FallbackFunctionBlockEdge(from, to) :-
   GlobalBlockEdge(from, to), 
   InFunction(from, f), FallbackFunction(f),
   InFunction(to, g), FallbackFunction(g).

% Analyze the fallback function paths with the
% conventional gas semantics, taking shortest paths
GasCostAnalysis = new CostAnalysis(
  Block_Gas, FallbackFunctionBlockEdge, 2300, min
).

% Analyze the fallback function paths with the
% updated gas semantics, taking shortest paths
EIP1884GasCostAnalysis = new CostAnalysis(
  EIP1884Block_Gas, FallbackFunctionBlockEdge, 2300, min
).

FallbackWillFailAnyway(n - 2300) :-
   GasCostAnalysis(*, n), n > 2300.

% fallback will fail with n - m additional gas
EIP1884FallbackWillFail(n - m) :-
   EIP1884GasCostAnalysis(block, n), n > 2300,
   GasCostAnalysis(block, m),
   !FallbackWillFailAnyway(*).
``` 

The analysis performs a gas cost computation over all possible paths in the fallback functions, using the gas cost semantics of both PRE and POST EIP-1884. In cases where there is a path that can complete in the former semantics but not the latter, we flag the smart contract.
