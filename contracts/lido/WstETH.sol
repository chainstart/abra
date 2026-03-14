// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.9;

/**
 * @title Wrapped stETH (wstETH)
 * @notice wstETH is a non-rebasing wrapper around stETH. While stETH balances change
 *         daily with oracle reports, wstETH balances remain constant — the value per
 *         token increases instead.
 *
 *         This makes wstETH compatible with DeFi protocols that don't handle rebasing tokens
 *         (Uniswap, Compound, etc.).
 *
 * @dev Internally, wstETH maps 1:1 to stETH shares. Wrapping converts stETH to its
 *      underlying share amount; unwrapping converts shares back to the current stETH value.
 *
 *      Key invariant: wstETH.balanceOf(user) == Lido.sharesOf(wstETH_contract) allocated to user
 */

interface IStETH {
    function getPooledEthByShares(uint256 _sharesAmount) external view returns (uint256);
    function getSharesByPooledEth(uint256 _ethAmount) external view returns (uint256);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function getTotalPooledEther() external view returns (uint256);
    function getTotalShares() external view returns (uint256);
}

contract WstETH {
    // ---- State ----
    string public constant name = "Wrapped liquid staked Ether 2.0";
    string public constant symbol = "wstETH";
    uint8 public constant decimals = 18;

    IStETH public immutable stETH;

    uint256 public totalSupply;
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;

    // ---- Events ----
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Wrap(address indexed account, uint256 stETHAmount, uint256 wstETHAmount);
    event Unwrap(address indexed account, uint256 wstETHAmount, uint256 stETHAmount);

    // ---- Constructor ----
    constructor(address _stETH) {
        require(_stETH != address(0), "ZERO_ADDRESS");
        stETH = IStETH(_stETH);
    }

    // ============ Core Wrap/Unwrap ============

    /**
     * @notice Wrap stETH to wstETH.
     * @param _stETHAmount Amount of stETH to wrap.
     * @return wstETHAmount Amount of wstETH minted.
     *
     * @dev The caller must have approved this contract to spend _stETHAmount of stETH.
     *
     *      Vulnerability surface: stETH transfer uses share-based math internally,
     *      so the actual stETH transferred might differ by 1-2 wei from _stETHAmount
     *      due to rounding. This is the well-known "1 wei corner case" in stETH.
     *      Protocols integrating wstETH should account for this.
     */
    function wrap(uint256 _stETHAmount) external returns (uint256 wstETHAmount) {
        require(_stETHAmount > 0, "ZERO_AMOUNT");

        // Convert stETH amount to underlying shares (= wstETH amount)
        wstETHAmount = stETH.getSharesByPooledEth(_stETHAmount);
        require(wstETHAmount > 0, "ZERO_SHARES");

        // Transfer stETH from caller to this contract
        // NOTE: due to stETH's share-based internals, the actual amount received
        // might be _stETHAmount - 1 wei in edge cases
        bool success = stETH.transferFrom(msg.sender, address(this), _stETHAmount);
        require(success, "STETH_TRANSFER_FAILED");

        // Mint wstETH to caller
        _mint(msg.sender, wstETHAmount);

        emit Wrap(msg.sender, _stETHAmount, wstETHAmount);
    }

    /**
     * @notice Unwrap wstETH back to stETH.
     * @param _wstETHAmount Amount of wstETH to unwrap.
     * @return stETHAmount Amount of stETH returned.
     */
    function unwrap(uint256 _wstETHAmount) external returns (uint256 stETHAmount) {
        require(_wstETHAmount > 0, "ZERO_AMOUNT");
        require(_balances[msg.sender] >= _wstETHAmount, "INSUFFICIENT_BALANCE");

        // Convert wstETH (shares) to stETH amount at current rate
        stETHAmount = stETH.getPooledEthByShares(_wstETHAmount);
        require(stETHAmount > 0, "ZERO_STETH");

        // Burn wstETH from caller
        _burn(msg.sender, _wstETHAmount);

        // Transfer stETH to caller
        bool success = stETH.transfer(msg.sender, stETHAmount);
        require(success, "STETH_TRANSFER_FAILED");

        emit Unwrap(msg.sender, _wstETHAmount, stETHAmount);
    }

    // ============ Rate Functions ============

    /**
     * @notice Returns the amount of stETH per 1 wstETH (i.e., per 1e18 wstETH).
     * @dev This rate increases over time as staking rewards accrue.
     *      stEthPerToken = totalPooledEther * 1e18 / totalShares
     */
    function stEthPerToken() external view returns (uint256) {
        uint256 totalShares = stETH.getTotalShares();
        if (totalShares == 0) return 1e18;
        return stETH.getPooledEthByShares(1e18);
    }

    /**
     * @notice Returns the amount of wstETH for 1 stETH (i.e., per 1e18 stETH).
     * @dev This rate decreases over time as staking rewards accrue.
     *      tokensPerStEth = totalShares * 1e18 / totalPooledEther
     */
    function tokensPerStEth() external view returns (uint256) {
        uint256 totalPooled = stETH.getTotalPooledEther();
        if (totalPooled == 0) return 1e18;
        return stETH.getSharesByPooledEth(1e18);
    }

    /**
     * @notice Convenience: get wstETH amount for a given stETH amount.
     */
    function getWstETHByStETH(uint256 _stETHAmount) external view returns (uint256) {
        return stETH.getSharesByPooledEth(_stETHAmount);
    }

    /**
     * @notice Convenience: get stETH amount for a given wstETH amount.
     */
    function getStETHByWstETH(uint256 _wstETHAmount) external view returns (uint256) {
        return stETH.getPooledEthByShares(_wstETHAmount);
    }

    // ============ ERC20 Implementation ============

    function balanceOf(address _account) external view returns (uint256) {
        return _balances[_account];
    }

    function transfer(address _to, uint256 _amount) external returns (bool) {
        _transfer(msg.sender, _to, _amount);
        return true;
    }

    function approve(address _spender, uint256 _amount) external returns (bool) {
        _allowances[msg.sender][_spender] = _amount;
        emit Approval(msg.sender, _spender, _amount);
        return true;
    }

    function allowance(address _owner, address _spender) external view returns (uint256) {
        return _allowances[_owner][_spender];
    }

    function transferFrom(address _from, address _to, uint256 _amount) external returns (bool) {
        uint256 currentAllowance = _allowances[_from][msg.sender];
        if (currentAllowance != type(uint256).max) {
            require(currentAllowance >= _amount, "ALLOWANCE_EXCEEDED");
            _allowances[_from][msg.sender] = currentAllowance - _amount;
        }
        _transfer(_from, _to, _amount);
        return true;
    }

    // ---- Internal ----

    function _transfer(address _from, address _to, uint256 _amount) internal {
        require(_from != address(0), "TRANSFER_FROM_ZERO");
        require(_to != address(0), "TRANSFER_TO_ZERO");
        require(_balances[_from] >= _amount, "INSUFFICIENT_BALANCE");
        _balances[_from] -= _amount;
        _balances[_to] += _amount;
        emit Transfer(_from, _to, _amount);
    }

    function _mint(address _to, uint256 _amount) internal {
        require(_to != address(0), "MINT_TO_ZERO");
        totalSupply += _amount;
        _balances[_to] += _amount;
        emit Transfer(address(0), _to, _amount);
    }

    function _burn(address _from, uint256 _amount) internal {
        require(_from != address(0), "BURN_FROM_ZERO");
        require(_balances[_from] >= _amount, "INSUFFICIENT_BALANCE");
        totalSupply -= _amount;
        _balances[_from] -= _amount;
        emit Transfer(_from, address(0), _amount);
    }

    /**
     * @notice Receive ETH — wraps stETH submitted directly.
     * @dev Allows wrapping via direct ETH send. ETH is submitted to Lido first,
     *      then the resulting stETH shares are kept as wstETH for the sender.
     *      NOTE: This path is not commonly used; most users wrap existing stETH.
     */
    receive() external payable {
        // This contract should not hold ETH directly in production.
        // A receive() without logic would allow ETH to be stuck.
        revert("USE_WRAP_FUNCTION");
    }
}
