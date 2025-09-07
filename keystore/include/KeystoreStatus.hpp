#pragma once

enum class KeystoreStatus 
{
    Success,
    KeystoreEmpty,
    KeystoreFull,
    DuplicateKeyId,
    InvalidKeyId,
    KeyIsEmpty
};