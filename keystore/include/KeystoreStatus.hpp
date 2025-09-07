#pragma once

enum class KeystoreStatus 
{
    Success,
    KeystoreEmpty,
    KeystoreFull,
    DuplicateKeyId,
    DuplicateKeyData,
    InvalidKeyId,
    KeyIsEmpty
};