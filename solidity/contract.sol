// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.7 <0.9.0;

// Task 6 Smart Contract
contract ItemStorage {
    // A singular item
    struct Item {
        uint256 id;
        string recycleState;
        uint256 addedToShelfTimestamp;
        uint256 expiryDateTimestamp;
        address[] history;
    }

    // Stores the address of the account that creates the contract
    address immutable internal owner;

    // Valid states and the how long to extends expiry time when reusing / recyling
    mapping (string => string) internal nextRecycleState;
    uint256 internal recycleExpiryExtension;
    string constant recycledState = "Recycled";
    bytes32 immutable internal recycledBytes;
    
    // Tracks the items and who owns them
    uint256 internal idCounter;
    mapping (address => uint256[]) internal inventory;
    mapping (uint256 => Item) internal idMappedItems;

    // Errors
    error InvalidItemType();
    error ItemNotOwned();
    error ContractOwnerOnly();
    error InvalidRecipient();

    // Events, could be used to integrate with external software etc
    event ItemTransferred(uint256 itemId, address sender, address receiver);
    event ItemStateChange(uint256 itemId, string oldState, string newState);

    // Prevents use of certain functions unless you are the contract owner
    modifier ownerOnly {
        if(msg.sender != owner) {
            revert ContractOwnerOnly();
        }

        _;
    }

    constructor(uint256 _recycleExpiryExtension) {
        owner = msg.sender;
        idCounter = 0;
        recycleExpiryExtension = _recycleExpiryExtension;
        recycledBytes = keccak256(bytes(recycledState));

        // Define the state transitions
        nextRecycleState["Milk"] = "Cheese";
        nextRecycleState["Cheese"] = recycledState;
        nextRecycleState["Bread"] = "Breadcrumbs";
        nextRecycleState["Breadcrumbs"] = recycledState;
    }

    // Create a new item and register it to the sender
    function createItem(string calldata itemType, uint256 expiryDateTimestamp) external {
        // Check the item type actually exists, if it does not then the next state will be empty
        if(bytes(nextRecycleState[itemType]).length == 0) {
            revert InvalidItemType();
        }

        // First address in the history is the creator
        address[] memory history = new address[](1);
        history[0] = msg.sender;

        // Create and store the item
        Item memory item = Item(idCounter, itemType, block.timestamp, expiryDateTimestamp, history);
        idMappedItems[idCounter] = item;
        inventory[msg.sender].push(idCounter);

        // Sequentially increment the ID
        idCounter++;
    }

    // Transfer an item between owners
    function transferItem(address receiver, uint256 itemId) external {
        // Can't transfer to self
        if(msg.sender == receiver) {
            revert InvalidRecipient();
        }

        uint256 i = 0;
        uint256[] storage senderInventory = inventory[msg.sender];
        uint256 inventorySize = senderInventory.length;

        // Find the item in their inventory
        for(i = 0; i < inventorySize; i++) {
            uint256 storedItemId = senderInventory[i];

            // Found it
            if(storedItemId == itemId) {
                // Transfer and update transaction history of the item
                senderInventory[i] = senderInventory[inventorySize - 1];
                senderInventory.pop();
                inventory[receiver].push(storedItemId);
                idMappedItems[itemId].history.push(receiver);
                emit ItemTransferred(itemId, msg.sender, receiver);
                return;
            }
        }

        // Item wasn't in their inventory, they must not own it
        revert ItemNotOwned();
    }

    // Retrieve an item by its ID
    // View functions have no cost if they are called externally only
    function getItemByID(uint256 itemId) view external returns (Item memory) {
        return idMappedItems[itemId];
    }

    // Initiate Recycle and Reuse
    // This would be called daily to automate the process
    function triggerRecycleAndReuse() ownerOnly external {
        uint256 id;
        uint256 maxCount = idCounter;
        uint256 timestamp = block.timestamp;

        // Loop every item
        for(id = 0; id < maxCount; id++) {
            Item storage item = idMappedItems[id];
            string memory currentState = item.recycleState;

            // Check if it is already recycled and make sure it is ready for recycling/reusing
            if(keccak256(bytes(currentState)) == recycledBytes || timestamp < item.expiryDateTimestamp) {
                continue;
            }

            string memory newState = nextRecycleState[currentState];
            emit ItemStateChange(id, currentState, newState);

            // Recycle or reuse using the state transitions
            item.recycleState = newState;
            // Increase the expiry time
            item.expiryDateTimestamp = item.expiryDateTimestamp + recycleExpiryExtension;
        }
    }

    // Get all items owned by the specified address
    // View functions have no cost if they are called externally only
    function getInventory(address adr) view external returns (Item[] memory) {
        uint256[] storage ownedItemIds = inventory[adr];
        uint256 inventorySize = ownedItemIds.length; // 1 SSTORE instead of m SSTORE
        Item[] memory items = new Item[](inventorySize);

        uint256 i;

        // Get all items in their inventory
        for(i = 0; i < inventorySize; i++) {
            items[i] = idMappedItems[ownedItemIds[i]];
        }

        return items;
    }

    // Get the caller's inventory
    // View functions have no cost if they are called externally only
    function getInventory() view external returns (Item[] memory) {
        return this.getInventory(msg.sender);
    }
}