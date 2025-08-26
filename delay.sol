// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * DelayGuard — Simple 24h withdrawal delay for Gnosis Safe
 * --------------------------------------------------------
 * Attach to a Safe with Safe.setGuard(address(this)).
 * Once enabled, any execTransaction will require a 24h cooldown
 * after proposal before it can be executed.
 *
 * - Propose: first call records hash + timestamp
 * - Execute: must re-call after 24h has passed to actually run
 */
interface ISafe {
    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes calldata signatures
    ) external returns (bool success);
}

contract DelayGuard {
    address public immutable safe;
    uint256 public constant DELAY = 24 hours;

    mapping(bytes32 => uint256) public queued; // txHash → timestamp

    event Queued(bytes32 indexed txHash, uint256 readyAt);
    event Executed(bytes32 indexed txHash);

    modifier onlySafe() {
        require(msg.sender == safe, "Only Safe");
        _;
    }

    constructor(address _safe) {
        require(_safe != address(0), "Invalid Safe");
        safe = _safe;
    }

    /**
     * Called by Safe before execTransaction.
     * - If not queued, record timestamp and revert.
     * - If queued but <24h, revert.
     * - If queued and >=24h, allow.
     */
    function checkTransaction(
        address,
        uint256,
        bytes calldata,
        uint8,
        uint256,
        uint256,
        uint256,
        address,
        address payable,
        bytes calldata,
        address,
        address
    ) external onlySafe {
        bytes32 txHash = keccak256(msg.data);
        uint256 t = queued[txHash];

        if (t == 0) {
            queued[txHash] = block.timestamp;
            emit Queued(txHash, block.timestamp + DELAY);
            revert("DelayGuard: queued, try again after 24h");
        }

        require(block.timestamp >= t + DELAY, "DelayGuard: still locked");
        emit Executed(txHash);
        delete queued[txHash];
    }

    function checkAfterExecution(bytes32, bool) external view onlySafe {}
}
