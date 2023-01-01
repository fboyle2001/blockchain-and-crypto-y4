// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.7 <0.9.0;

contract ItemStorage {
    struct Item {
        uint256 id;
        string recycleState;
        uint256 addedToShelfTimestamp;
        uint256 expiryDateTimestamp;
    }

    uint256 internal idCounter;
    mapping (string => string) internal nextRecycleState;
    uint256 internal recycleExpiryExtension;

    error InvalidItemType();
    error ItemNotOwned();

    constructor(uint256 _recycleExpiryExtension) {
        idCounter = 0;
        recycleExpiryExtension = _recycleExpiryExtension;

        nextRecycleState["Milk"] = "Cheese";
        nextRecycleState["Cheese"] = "";
        nextRecycleState["Bread"] = "Breadcrumbs";
        nextRecycleState["Breadcrumbs"] = "";
    }
    
    mapping (address => uint256[]) internal inventory;
    mapping (uint256 => Item) internal idMappedItems;

    event ItemExpired(address owner, Item item);

    // Create: O(1)
    function createItem(string calldata itemType, uint256 expiryDateTimestamp) external {
        if(bytes(nextRecycleState[itemType]).length == 0) {
            revert InvalidItemType();
        }

        Item memory item = Item(idCounter, itemType, block.timestamp, expiryDateTimestamp);
        idMappedItems[idCounter] = item;
        inventory[msg.sender].push(idCounter);
        idCounter++;
    }

    // Transfer: O(m)
    function transferItem(address receiver, uint256 itemId) external {
        uint256 i = 0;
        uint256[] storage senderInventory = inventory[msg.sender];
        uint256 inventorySize = senderInventory.length;

        for(i = 0; i < inventorySize; i++) {
            uint256 storedItemId = senderInventory[i];

            if(storedItemId == itemId) {
                senderInventory[i] = senderInventory[inventorySize - 1];
                senderInventory.pop();
                inventory[receiver].push(storedItemId);
                return;
            }
        }

        revert ItemNotOwned();
    }

    // Item by ID: O(1)
    function getItemByID(uint256 itemId) view external returns (Item memory) {
        return idMappedItems[itemId];
    }

    // Initiate Recycle and Reuse: O(n)
    function triggerRecycleAndReuse() external {
        uint256 id;
        uint256 maxCount = idCounter;

        for(id = 0; id < maxCount; id++) {
            Item storage item = idMappedItems[id];

            if(bytes(item.recycleState).length == 0 || block.timestamp < item.expiryDateTimestamp) {
                continue;
            }

            item.recycleState = nextRecycleState[idMappedItems[id].recycleState];
            item.expiryDateTimestamp = item.expiryDateTimestamp + recycleExpiryExtension;
        }
    }

    // Invent by Adr: O(m)
    function getInventory(address owner) view external returns (Item[] memory) {
        uint256[] storage ownedItemIds = inventory[owner];
        uint256 inventorySize = ownedItemIds.length; // 1 SSTORE instead of m SSTORE
        Item[] memory items = new Item[](inventorySize);

        uint256 i;

        for(i = 0; i < inventorySize; i++) {
            items[i] = idMappedItems[ownedItemIds[i]];
        }

        return items;
    }

    function getInventory() view external returns (Item[] memory) {
        return this.getInventory(msg.sender);
    }
}