# PASD core service

## Encryption

```
- Check if all registered keys available
- Decrypt batabase with available keys
- Create record for new secret
--- loop ---
- Find 100% keys group
- Encrypt secret vaue with hashed sum of keys
- Store encripted value as:
  KeysHashSum: {
    Encripted secret
    other info
  }
--- loop ---
- Loop by 100% keys groups and encript database
:_keyshash_0x00000000_encripted_db_[...]

-------------------------------------------------
I.   Check if all registered keys available

II.  Decrypt batabase with available keys groups
  KeyA - 100%, KeyB - 30%, KeyC - 50%, KeyD - 80%
  Available groups:
    - KeyA         : Group1 (if key >= 100%, use it alone)
    - KeyB, KeyD   : Group2 (valid group if k >= 100%)
    - KeyC, KeyD   : Group3

┌───────────────────────────────────────────────┐
│ Encrypted DataBase                            │
│                                               │
│ Group1Hash_len_db|Group2Hash_...              │
└───────────────────────────────────────────────┘

III. Create secret record with all info about it.
  type, name, urls, login, data, 
  + empty values field (HashMap)

IV.  Loop through all key groups and encrypt value of secret

V.   Store encrypted value in hashmap
  { GroupHash: EncryptedValue }

VI.  Loop through all key groups and encrypt Database

VII. Save datebase
```
