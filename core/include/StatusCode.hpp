#pragma once

enum class StatusCode
{
    Success,
    KeystoreEmpty,
    KeystoreFull,
    DuplicateKeyId,
    DuplicateKeyData,
    InvalidKeyId,
    KeyDataIsEmpty
};