// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SampleVault {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }
}
