pragma solidity ^0.4.24;

/**
 * Math operations with safety checks
 */
contract SafeMath {

    function safeMul(uint a, uint b)internal pure returns (uint) {
        uint c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

    function safeDiv(uint a, uint b)internal pure returns (uint) {
        assert(b > 0);
        uint c = a / b;
        assert(a == b * c + a % b);
        return c;
    }

    function safeSub(uint a, uint b)internal pure returns (uint) {
        assert(b <= a);
        return a - b;
    }

    function safeAdd(uint a, uint b)internal pure returns (uint) {
        uint c = a + b;
        assert(c>=a && c>=b);
        return c;
    }
}

/*
 * Base Token for ERC20 compatibility
 * ERC20 interface 
 * see https://github.com/ethereum/EIPs/issues/20
 */
contract ERC20 {
    //function totalSupply() public view returns (uint256);
    function balanceOf(address who) public view returns (uint);
    function allowance(address owner, address spender) public view returns (uint);
    function transfer(address to, uint value) public returns (bool ok);
    function transferFrom(address from, address to, uint value) public returns (bool);
    function approve(address spender, uint value) public returns (bool);
    event Transfer(address indexed from, address indexed to, uint value);
    event Transfer(address indexed from, address indexed to, uint value, bytes data);
    event Approval(address indexed owner, address indexed spender, uint value);
}

/*
 * Ownable
 *
 * Base contract with an owner contract.
 * Provides onlyOwner modifier, which prevents function from running if it is called by anyone other than the owner.
 */
contract Ownable {
    /* Address of the owner */
    address public owner;

    // list of all the admins in the system
    mapping (address => bool) internal admins;

    constructor() public {
        owner = msg.sender;
        admins[msg.sender] = true;
    }

    modifier onlyOwner() {
        require(msg.sender == owner,"Only Token Owner can perform this action");
        _;
    }
    
    modifier isAdmin() {
        require(admins[msg.sender] == true,"Only admin can call this function");
        _;
    }

    function transferOwnership(address _owner) public onlyOwner{
        require(_owner != owner,"New Owner is the same as existing Owner");
        require(_owner != address(0), "Empty Address provided");
        owner = _owner;
    }

    function makeAdmin(address target) public onlyOwner{
        require(target != address(0), "Empty Address provided");
        admins[target] = true;
    }

    function revokeAdmin(address target) public onlyOwner {
        require(target != address(0), "Empty Address provided");
        admins[target] = false;
    }
}
/**
 * Freezable allows admin(s) to freeze token of a particular account (temporarily)
 * Or all account (during ICO)
 */

contract Freezable is Ownable{

    // determines if all account got frozen.
    bool internal accountsFrozen;

    // list of the frozen accounts
    mapping (address => bool) public frozenAccount;

    event FrozenFunds(address target, bool frozen);

    constructor() public {
        admins[msg.sender] = true;
    }

    function freezeAccount(address target) public onlyOwner{
        require(target != address(0), "Empty Address provided");
        frozenAccount[target] = true;
        emit FrozenFunds(target, true);
    }

    function unFreezeAccount(address target) public onlyOwner{
        require(target != address(0), "Empty Address provided");
        frozenAccount[target] = false;
        emit FrozenFunds(target, false);
    }
    

    function freezeAll() public onlyOwner{
        accountsFrozen = true;
    }

    function unfreezeAll() public onlyOwner {
        accountsFrozen = false;
    }

}

/**
 * Standard ERC20 token with Short Hand Attack and approve() race condition mitigation.
 *
 * Based on code by FirstBlood:
 * https://github.com/Firstbloodio/token/blob/master/smart_contract/FirstBloodToken.sol
 */
contract StandardToken is ERC20, SafeMath, Freezable{

    event Burn(address indexed from, uint value);

    /* Actual balances of token holders */
    mapping(address => uint) balances;
    uint public totalSupply;

    /* approve() allowances */
    mapping (address => mapping (address => uint)) internal allowed;
    
    /**
     *
     * Fix for the ERC20 short address attack
     *
     * http://vessenes.com/the-erc20-short-address-attack-explained/
     */
    modifier onlyPayloadSize(uint size) {
        if(msg.data.length < size + 4) {
            revert("Payload attack");
        }
        _;
    }

    /**
     *
     * Transfer with ERC20 specification
     *
     * @param _to    Receiver address.
     * @param _value Amount of tokens that will be transferred.
     * http://vessenes.com/the-erc20-short-address-attack-explained/
     */
    function transfer(address _to, uint _value) 
    onlyPayloadSize(2 * 32)
    public
    returns (bool)
    {
        require(_to != address(0), "No address specified");
        require(balances[msg.sender] >= _value, "Insufficiently fund");
        require(!frozenAccount[msg.sender],"User account frozen");
        require(!accountsFrozen || admins[msg.sender] == true, "Transfer not available at the moment");

        balances[msg.sender] = safeSub(balances[msg.sender], _value);
        balances[_to] = safeAdd(balances[_to], _value);
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    /**
     * @dev Transfer the specified amount of tokens to the specified address.
     *    Invokes the `tokenFallback` function if the recipient is a contract.
     *    The token transfer fails if the recipient is a contract
     *    but does not implement the `tokenFallback` function
     *    or the fallback function to receive funds.
     *
     * @param _to    Receiver address.
     * @param _value Amount of tokens that will be transferred.
     * @param _data    Transaction metadata.
     */
    function transfer(address _to, uint _value, bytes _data)
    onlyPayloadSize(2 * 32) 
    public
    returns (bool success) 
    {
        require(_to != address(0), "No address specified");
        require(balances[msg.sender] >= _value, "Insufficiently fund");
        require(!frozenAccount[msg.sender],"User account frozen");
        require(!accountsFrozen || admins[msg.sender] == true, "Transfer not available at the moment");

        balances[msg.sender] = safeSub(balances[msg.sender], _value);
        balances[_to] = safeAdd(balances[_to], _value);
        emit Transfer(msg.sender, _to, _value, _data);
        return true;
    }

    function transferFrom(address _from, address _to, uint _value)
    public
    returns (bool)
    {
        require(_to != address(0), "Empty address specified as Receiver");
        require(_from != address(0), "Empty Address provided for Sender");
        require(_value <= balances[_from], "Insufficiently fund");
        require(_value <= allowed[_from][msg.sender], "You can't spend the speficied amount from this Account");
        require(!frozenAccount[_from],"Sender account frozen");
        require(!frozenAccount[msg.sender],"Spender account frozen");
        require(!accountsFrozen || admins[msg.sender] == true, "Transfer not available at the moment");
        uint _allowance = allowed[_from][msg.sender];
        balances[_to] = safeAdd(balances[_to], _value);
        balances[_from] = safeSub(balances[_from], _value);
        allowed[_from][msg.sender] = safeSub(_allowance, _value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    function transferToCrowdsale(address _to, uint _value)
    public
    onlyPayloadSize(2 * 32) 
    onlyOwner
    returns (bool success)
    {
        require(_to != address(0), "Innvalid address provided");
        if (balances[msg.sender] >= _value && _value > 0) {
            balances[msg.sender] = safeSub(balances[msg.sender], _value);
            balances[_to] = safeAdd(balances[_to], _value);
            emit Transfer(msg.sender, _to, _value);
            return true;
        }
        else { 
            return false; 
        }
    }

    function balanceOf(address _owner) public view returns (uint) {
        return balances[_owner];
    }

    function approve(address _spender, uint _value) 
    public
    returns (bool)
    {
        require(_spender != address(0), "Invalid Address");

        // To change the approve amount you first have to reduce the addresses`
        //    allowance to zero by calling `approve(_spender, 0)` if it is not
        //    already 0 to mitigate the race condition described here:
        //    https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
        //if ((_value != 0) && (allowed[msg.sender][_spender] != 0)) throw;
        require(_value == 0 || allowed[msg.sender][_spender] == 0, "Spender allowance must be zero before approving new allowance");
        require(_value <= balances[msg.sender],"Insufficient balance in owner's account");
        require(_value >= 0, "Cannot approve negative amount");
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    /**
     * approve should be called when allowed[_spender] == 0. To increment
     * allowed value is better to use this function to avoid 2 calls (and wait until
     * the first transaction is mined)
     * From MonolithDAO Token.sol
     */
    function increaseApproval(address _spender, uint _addedValue) public returns (bool) {
        allowed[msg.sender][_spender] = safeAdd(allowed[msg.sender][_spender], _addedValue);
        emit Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
        return true;
    }

    function decreaseApproval(address _spender, uint _subtractedValue) public returns (bool) {
        require(_subtractedValue >= 0 && _subtractedValue <= balances[msg.sender], "Invalid Amount");
        uint oldValue = allowed[msg.sender][_spender];
        if (_subtractedValue > oldValue) {
            allowed[msg.sender][_spender] = 0;
        } else {
            allowed[msg.sender][_spender] = safeSub(oldValue, _subtractedValue);
        }
        emit Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint) {
        return allowed[_owner][_spender];
    }

    function burn(address from, uint amount) public onlyOwner{
        require(balances[from] >= amount && amount > 0, "Insufficient amount or invalid amount specified");
        balances[from] = safeSub(balances[from],amount);
        totalSupply = safeSub(totalSupply, amount);
        emit Transfer(from, address(0), amount);
        emit Burn(from, amount);
    }

    function burn(uint amount) public onlyOwner {
        burn(msg.sender, amount);
    }
}

contract NurKoin is StandardToken {
    string public name;
    uint8 public decimals; 
    string public symbol;

    constructor() public{
        decimals = 18;     // Amount of decimals for display purposes
        totalSupply = 2200000000 * 1 ether;     // Update total supply
        balances[msg.sender] = totalSupply;    // Give the creator all initial tokens
        name = "NurKoin";    // Set the name for display purposes
        symbol = "NUR";    // Set the symbol for display purposes
    }

    /* Approves and then calls the receiving contract */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData) 
    public
    returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        if(!_spender.call(bytes4(bytes32(keccak256("receiveApproval(address,uint256,address,bytes)"))), msg.sender, _value, this, _extraData)) { revert(); }
        return true;
    }

    // can accept ether
    function() public payable{
        revert("Token does not accept ETH");
    }
}
