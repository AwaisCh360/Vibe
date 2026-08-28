pragma solidity ^0.4.15;
contract Vulnerable {
    mapping(address => uint) public balances;
    function withdraw() public {
        uint bal = balances[msg.sender];
        require(bal > 0);
        msg.sender.call.value(bal)(""); // Reentrancy
        balances[msg.sender] = 0;
    }
}
