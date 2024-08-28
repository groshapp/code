// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.9;

import "@account-abstraction/contracts/core/EntryPoint.sol";
import "@account-abstraction/contracts/interfaces/IAccount.sol";
import "@openzeppelin/contracts/utils/Create2.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

interface IAave {
    function supply(
        address asset,
        uint256 amount,
        address onBehalfOf,
        uint16 referralCode
    ) external;

    function withdraw(address asset, uint256 amount, address to) external;
}

interface IErc20 {
    function approve(address spender, uint256 value) external returns (bool);
}

/// @author reprezenter
/// @title Account Abstraction implementation
/// for internal use only, do not interact without deeply risk understanding
contract Account is IAccount {
    uint256 private passCounter;
    uint256 private rPassCounter;
    bytes32 private hash;
    bytes32 private pass;
    bytes32 private rPass;
    bytes32 private rValidationCode;
    uint256 private setRValidationCodeBlock;
    bytes32 private rec;
    uint256 private setHashBlock;
    address private immutable entryPointAddress;
    address private immutable payOutAddress;
    event Received(address, uint);
    event TimelockInit(string);

    address private constant AAVE_POOL =
        0x6Ae43d3271ff6888e7Fc43Fd7321a503ff738951;
    address private constant USDC_ADDR =
        0x94a9D9AC8a22534E3FaCa9F4e7F2E2cf85d5E4C8;
    bytes4 private constant SET_USEROP_SIGNATURE = 0xf8508e88;
    bytes4 private constant SET_USEROP_RECOVERY_SIGNATURE = 0xe4b056b0;

    uint private constant MAX_TIMESTAMP_DELAY = 604800;
    uint private constant MAX_TIMESTAMP_EXECUTE_DELAY = 86400;

    bytes32 private queued;

    constructor(
        address entryPoint,
        address payOutTo,
        bytes32 password,
        bytes32 recoveryPassword
    ) {
        entryPointAddress = entryPoint;
        payOutAddress = payOutTo;
        pass = password;
        rPass = recoveryPassword;
    }

    modifier onlyFromEntryPoint() {
        _onlyFromEntryPoint();
        _;
    }

    // directly from entryPoint, or through the account itself (which gets redirected through execute())
    function _onlyFromEntryPoint() internal view {
        
        require(
            msg.sender == entryPointAddress || msg.sender == address(this),
            "only from entry point"
        );
    }

    function getIsPayOutAddress() external view returns (bool) {
        return payOutAddress != address(0);
    }

    function getCounter() external view returns (uint256) {
        return passCounter;
    }

    function getRCounter() external view returns (uint256) {
        return rPassCounter;
    }

    // change password
    function setPassword(
        bytes calldata _data,
        uint256 _timestamp,
        bytes32 nextPass
    ) external onlyFromEntryPoint returns (bool) {
        beforeExecute(nextPass);
        emit TimelockInit("Password change");
        queue(0, _data, _timestamp);
        return true;
    }

    // change password from recovery
    function setRecoveryPassword(
        bytes calldata _data,
        uint256 _timestamp,
        bytes32 nextRPassword
    ) external onlyFromEntryPoint returns (bool) {
        rPass = nextRPassword;
        rPassCounter++;
        emit TimelockInit("Password recovered");
        queue(0, _data, _timestamp);
        return true;
    }

    // change password timelocked
    function setPass(bytes32 nextPass) public returns (bool) {
        if (msg.sender != address(this)) {
            revert("only for internal use");
        }
        beforeExecute(nextPass);
        return true;
    }

    // change password from recovery timelocked
    function setRecoveryPass(bytes32 nextPass, bytes32 nextRPassword) public {
        if (msg.sender != address(this)) {
            revert("only for internal use");
        }
        pass = nextPass;
        rPass = nextRPassword;
        rPassCounter++;
    }

    // pay out
    function payOut(
        bytes calldata _data,
        uint256 _timestamp,
        bytes32 nextPass
    ) external onlyFromEntryPoint returns (bool) {
        beforeExecute(nextPass);
        emit TimelockInit("Pay out");
        queue(0, _data, _timestamp);
        return true;
    }

    //if payOutAddress provided on creation only there transfer is possible, otherwise to provided addres
    function payOutToken(bytes32 nextPass, uint amount, address to) public {
        beforeExecute(nextPass);
        uint256 balance = IERC20(USDC_ADDR).balanceOf(address(this));
        require(amount <= balance, "insufficient funds");
        if (payOutAddress != address(0)) {
            IERC20(USDC_ADDR).transfer(payOutAddress, amount);
        } else {
            require(to != address(0), "payout to addres 0");
            IERC20(USDC_ADDR).transfer(to, amount);
        }
    }

    //prevent mempool manipulation before execute trnsaction hash is saved
    function setUserOpHash(
        bytes32 _hash,
        bytes32 nextPass
    ) external onlyFromEntryPoint {
        beforeExecute(nextPass);
        setHashBlock = block.number;
        hash = _hash;
    }

    //same as setUserOpHash for recovery case
    function setUserOpHashRecovery(
        bytes32 _hash,
        bytes32 nextPass
    ) external onlyFromEntryPoint {
        rPass = nextPass;
        rPassCounter++;
        setHashBlock = block.number;
        hash = _hash;
    }

    function getHash() external view returns (bytes32) {
        return hash;
    }

    //timelock related functions
    function getTxId(
        uint256 _value,
        bytes calldata _data,
        uint256 _timestamp
    ) private pure returns (bytes32) {
        return keccak256(abi.encode(_value, _data, _timestamp));
    }

    function queue(
        uint256 _value,
        bytes calldata _data,
        uint256 _timestamp
    ) private returns (bytes32 txId) {
        txId = getTxId(_value, _data, _timestamp);
        if (_timestamp > block.timestamp + MAX_TIMESTAMP_DELAY) {
            revert("timestamp exceeds max allowed delay");
        }
        queued = txId;
    }

    function executeQueue(
        uint256 _value,
        bytes calldata _data,
        uint256 _timestamp
    ) external payable returns (bytes memory) {
        bytes32 txId = getTxId(_value, _data, _timestamp);
        if (queued != txId) {
            revert("Invalid txId");
        }
        if (block.timestamp < _timestamp) {
            revert("Timestamp error");
        }
        if (block.timestamp > _timestamp + MAX_TIMESTAMP_EXECUTE_DELAY) {
            queued = 0;
            bytes memory empty = "";
            return empty;
        }

        queued = 0;

        (bool ok, bytes memory res) = address(this).call{value: _value}(_data);
        if (!ok) {
            revert("Tx failed");
        }
        return res;
    }

    function cancelQueue(bytes32 nextPass) external onlyFromEntryPoint {
        beforeExecute(nextPass);
        queued = 0;
    }

    function isQueued() external view returns (bytes32) {
        return queued;
    }
    //end timelock related functions

    // @inheritdoc IAccount
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256
    ) external view returns (uint256 validationData) {
        if (passCounter == 0 && userOp.initCode.length != 0 && hash == 0) {
            return 0;
        }

        bool passValidation = false;
        if (
            keccak256(abi.encodePacked(pass)) ==
            keccak256(
                abi.encodePacked(keccak256(abi.encodePacked(userOp.signature)))
            )
        ) {
            passValidation = true;
        }
        if (
            keccak256(abi.encodePacked(rPass)) ==
            keccak256(
                abi.encodePacked(keccak256(abi.encodePacked(userOp.signature)))
            )
        ) {
            passValidation = true;
        }
        bool hashVerificationNonRequired = false;
        if (
            bytes4(userOp.callData) == SET_USEROP_SIGNATURE ||
            bytes4(userOp.callData) == SET_USEROP_RECOVERY_SIGNATURE
        ) {
            hashVerificationNonRequired = true;
        }

        if (
            passValidation &&
            (hashVerificationNonRequired ||
                (setHashBlock != 0 &&
                    setHashBlock < block.number &&
                    hash != 0 &&
                    keccak256(abi.encodePacked(hash)) ==
                    keccak256(
                        abi.encodePacked(
                            keccak256(
                                abi.encodePacked(userOpHash, userOp.signature)
                            )
                        )
                    )))
        ) {
            return 0;
        }
        return 1;
    }

    receive() external payable {
        emit Received(msg.sender, msg.value);
    }

    // init account with userOp.initCode and this function
    function initAccount(bytes32 nextPass) external onlyFromEntryPoint {
        beforeExecute(nextPass);
    }

    // all exection functions should do this at the begining
    function beforeExecute(bytes32 nextPass) private {
        pass = nextPass;
        passCounter++;
        setHashBlock = 0;
    }

    // erc20 token aproval to aave contract
    function approveErc20(
        bytes32 nextPass,
        address spender,
        uint256 value
    ) external onlyFromEntryPoint returns (bool) {
        beforeExecute(nextPass);
        return IErc20(USDC_ADDR).approve(spender, value);
    }

    // withdraw from aave to acoount
    function aaveWithdraw(
        bytes32 nextPass,
        address asset,
        uint256 amount
    ) external onlyFromEntryPoint {
        beforeExecute(nextPass);
        address to = address(this);
        if (amount == 0) {
            amount = type(uint256).max;
        }
        IAave(AAVE_POOL).withdraw(asset, amount, to);
    }

    // supply to aave from account
    function aaveSupply(
        bytes32 nextPass,
        address asset,
        uint256 amount,
        uint16 referralCode
    ) external onlyFromEntryPoint {
        beforeExecute(nextPass);
        address onBehalfOf = address(this);
        IAave(AAVE_POOL).supply(asset, amount, onBehalfOf, referralCode);
    }
}

/// @author reprezenter
/// @title Account Abstraction Factory implementation
contract AccountFactory {
    function createAccount(
        address entryPointAddress,
        address payOutAddress,
        bytes32 password,
        bytes32 rPassword
    ) external returns (address) {
        bytes memory bytecode = abi.encodePacked(
            type(Account).creationCode,
            abi.encode(entryPointAddress),
            abi.encode(payOutAddress),
            abi.encode(password),
            abi.encode(rPassword)
        );
        address addr = Create2.computeAddress(password, keccak256(bytecode));
        if (addr.code.length > 0) {
            return addr;
        }
        return deploy(password, bytecode);
    }

    function deploy(
        bytes32 salt,
        bytes memory bytecode
    ) internal returns (address addr) {
        require(bytecode.length != 0, "Create2: bytecode length is zero");
        /// @solidity memory-safe-assembly
        assembly {
            addr := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }
        require(addr != address(0), "Create2: Failed on deploy");
    }
}
