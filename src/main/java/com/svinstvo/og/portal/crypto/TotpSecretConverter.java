package com.svinstvo.og.portal.crypto;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

@Converter
public class TotpSecretConverter implements AttributeConverter<String, String> {

    private final TotpSecretEncryptor encryptor;

    public TotpSecretConverter(TotpSecretEncryptor encryptor) {
        this.encryptor = encryptor;
    }

    @Override
    public String convertToDatabaseColumn(String secret) {
        return encryptor.encrypt(secret);
    }

    @Override
    public String convertToEntityAttribute(String dbValue) {
        return encryptor.decrypt(dbValue);
    }
}
