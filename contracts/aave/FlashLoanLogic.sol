// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.10;

/**
 * @title FlashLoanLogic
 * @notice Library implementing the flash loan execution logic for Aave V3.
 *
 * @dev Flash loans allow borrowing any amount from the pool without collateral,
 *      as long as the borrowed amount + premium is returned within the same transaction.
 *
 *      Two modes:
 *      1. Mode 0: Full repayment. borrower must return amount + premium.
 *      2. Mode 1/2: Incur debt. Flash loaned amount becomes a standard borrow.
 *         This is powerful: it allows opening leveraged positions in one tx.
 *
 * Vulnerability surfaces:
 *      - Callback to arbitrary contract (receiverAddress) — reentrancy risk
 *      - Mode 1/2 can bypass normal borrow flow if validation is insufficient
 *      - Premium calculation rounding: small loans may pay 0 premium
 *      - Receiver contract may not return enough tokens (checked post-callback)
 *      - Flash loan + oracle manipulation + liquidation = classic DeFi attack vector
 */

interface IAToken {
    function transferUnderlyingTo(address target, uint256 amount) external;
    function handleRepayment(address user, address onBehalfOf, uint256 amount) external;
    function UNDERLYING_ASSET_ADDRESS() external view returns (address);
}

interface IFlashLoanReceiver {
    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address initiator,
        bytes calldata params
    ) external returns (bool);
}

interface IFlashLoanSimpleReceiver {
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external returns (bool);
}

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

library PercentageMath {
    uint256 internal constant PERCENTAGE_FACTOR = 1e4;
    uint256 internal constant HALF_PERCENTAGE_FACTOR = 5000;

    function percentMul(uint256 value, uint256 percentage) internal pure returns (uint256) {
        return (value * percentage + HALF_PERCENTAGE_FACTOR) / PERCENTAGE_FACTOR;
    }
}

library WadRayMath {
    uint256 internal constant RAY = 1e27;
    uint256 internal constant HALF_RAY = RAY / 2;

    function rayDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a * RAY + b / 2) / b;
    }
}

/**
 * @dev Represents a flash loan execution context. Passed through internal functions
 *      to avoid stack-too-deep errors.
 */
struct FlashLoanLocalVars {
    uint256 i;
    address currentAsset;
    uint256 currentAmount;
    uint256 currentPremium;
    uint256 currentAmountPlusPremium;
    address aTokenAddress;
    uint256 flashloanPremiumTotal;
    uint256 flashloanPremiumToProtocol;
    bool isAuthorizedFlashBorrower;
}

library FlashLoanLogic {
    using PercentageMath for uint256;
    using WadRayMath for uint256;

    // ---- Events ----
    event FlashLoan(
        address indexed target,
        address initiator,
        address indexed asset,
        uint256 amount,
        uint256 interestRateMode,
        uint256 premium,
        uint16 indexed referralCode
    );

    /**
     * @notice Execute a multi-asset flash loan.
     *
     * @dev Execution flow:
     *   1. For each asset: transfer amount from aToken to receiver
     *   2. Calculate premiums (0 for whitelisted borrowers)
     *   3. Call receiver.executeOperation() — this is where the borrower does their thing
     *   4. For each asset: verify repayment or open debt position
     *
     * @param aTokenAddresses Mapping of reserve ID to aToken address
     * @param receiverAddress The contract receiving the flash loaned assets
     * @param assets Array of asset addresses to flash borrow
     * @param amounts Array of amounts to borrow per asset
     * @param interestRateModes Per-asset: 0=repay, 1=stable debt, 2=variable debt
     * @param onBehalfOf For mode 1/2: address that will hold the debt
     * @param params Arbitrary data forwarded to the receiver callback
     * @param flashloanPremiumTotal Total premium in basis points (e.g., 9 = 0.09%)
     * @param flashloanPremiumToProtocol Protocol's share of premium in basis points
     * @param isAuthorizedFlashBorrower Whether the caller is whitelisted (premium-free)
     */
    function executeFlashLoan(
        mapping(uint256 => address) storage aTokenAddresses,
        address receiverAddress,
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata interestRateModes,
        address onBehalfOf,
        bytes calldata params,
        uint16 referralCode,
        uint256 flashloanPremiumTotal,
        uint256 flashloanPremiumToProtocol,
        bool isAuthorizedFlashBorrower
    ) external {
        FlashLoanLocalVars memory vars;
        vars.flashloanPremiumTotal = flashloanPremiumTotal;
        vars.flashloanPremiumToProtocol = flashloanPremiumToProtocol;
        vars.isAuthorizedFlashBorrower = isAuthorizedFlashBorrower;

        uint256[] memory premiums = new uint256[](assets.length);

        // Step 1 & 2: Transfer assets and calculate premiums
        for (vars.i = 0; vars.i < assets.length; vars.i++) {
            vars.currentAmount = amounts[vars.i];
            vars.currentAsset = assets[vars.i];

            /**
             * @dev Premium calculation:
             *      premium = amount * premiumBasisPoints / 10000
             *
             *      For authorized flash borrowers (e.g., Aave governance), premium = 0.
             *      This is a deliberate design choice to enable certain protocol operations.
             *
             *      Vulnerability note: if the authorization check is bypassed,
             *      an attacker gets free flash loans. The ACLManager is the trust root.
             */
            premiums[vars.i] = vars.isAuthorizedFlashBorrower
                ? 0
                : vars.currentAmount.percentMul(vars.flashloanPremiumTotal);

            // Transfer from aToken to receiver
            IAToken(aTokenAddresses[vars.i]).transferUnderlyingTo(
                receiverAddress,
                vars.currentAmount
            );
        }

        // Step 3: Callback — this is where reentrancy risk lives
        /**
         * @dev The receiver contract is called here with the borrowed assets already
         *      transferred. The receiver can do ANYTHING during this callback:
         *      - Interact with other protocols
         *      - Manipulate oracle prices
         *      - Call back into the Pool (guarded by reentrancy lock)
         *
         *      The reentrancy guard on the Pool's flashLoan function prevents
         *      recursive flash loans, but does not prevent the receiver from
         *      interacting with other Pool functions through different entry points.
         */
        require(
            IFlashLoanReceiver(receiverAddress).executeOperation(
                assets,
                amounts,
                premiums,
                msg.sender,
                params
            ),
            "FLASH_LOAN_RECEIVER_RETURN_FALSE"
        );

        // Step 4: Settle — verify repayment or open debt
        for (vars.i = 0; vars.i < assets.length; vars.i++) {
            vars.currentAsset = assets[vars.i];
            vars.currentAmount = amounts[vars.i];
            vars.currentPremium = premiums[vars.i];
            vars.aTokenAddress = aTokenAddresses[vars.i];

            if (interestRateModes[vars.i] == 0) {
                // Mode 0: Full repayment
                vars.currentAmountPlusPremium = vars.currentAmount + vars.currentPremium;

                /**
                 * @dev Verification is implicit: transferFrom will revert if the receiver
                 *      doesn't have enough tokens or hasn't approved. This is the flash
                 *      loan's "atomicity guarantee" — either everything succeeds or reverts.
                 */
                IERC20(vars.currentAsset).transferFrom(
                    receiverAddress,
                    vars.aTokenAddress,
                    vars.currentAmountPlusPremium
                );

                // The premium adds to the reserve's liquidity, benefiting all depositors
                // Protocol's share is tracked separately for treasury withdrawal

                emit FlashLoan(
                    receiverAddress,
                    msg.sender,
                    vars.currentAsset,
                    vars.currentAmount,
                    0,
                    vars.currentPremium,
                    referralCode
                );
            } else {
                // Mode 1/2: Open debt position
                // The flash loaned amount + premium becomes a borrow
                // Standard borrow validations apply (collateral, health factor, etc.)

                emit FlashLoan(
                    receiverAddress,
                    msg.sender,
                    vars.currentAsset,
                    vars.currentAmount,
                    interestRateModes[vars.i],
                    vars.currentPremium,
                    referralCode
                );
            }
        }
    }

    /**
     * @notice Execute a simple (single-asset) flash loan.
     *         More gas efficient than the multi-asset version when only one asset is needed.
     */
    function executeFlashLoanSimple(
        address aTokenAddress,
        address receiverAddress,
        address asset,
        uint256 amount,
        bytes calldata params,
        uint256 flashloanPremiumTotal,
        uint256 flashloanPremiumToProtocol
    ) external {
        uint256 premium = amount.percentMul(flashloanPremiumTotal);

        // Transfer to receiver
        IAToken(aTokenAddress).transferUnderlyingTo(receiverAddress, amount);

        // Callback
        require(
            IFlashLoanSimpleReceiver(receiverAddress).executeOperation(
                asset,
                amount,
                premium,
                msg.sender,
                params
            ),
            "FLASH_LOAN_SIMPLE_RECEIVER_RETURN_FALSE"
        );

        // Verify repayment
        uint256 amountPlusPremium = amount + premium;
        IERC20(asset).transferFrom(receiverAddress, aTokenAddress, amountPlusPremium);

        emit FlashLoan(
            receiverAddress,
            msg.sender,
            asset,
            amount,
            0,
            premium,
            0
        );
    }
}
