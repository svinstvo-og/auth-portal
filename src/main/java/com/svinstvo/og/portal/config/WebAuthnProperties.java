package com.svinstvo.og.portal.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "app.webauthn")
public class WebAuthnProperties {

    private String rpId   = "localhost";
    private String rpName = "Auth Portal";
    private String origin = "http://localhost:8080";

    public String getRpId()              { return rpId; }
    public void setRpId(String rpId)     { this.rpId = rpId; }
    public String getRpName()            { return rpName; }
    public void setRpName(String n)      { this.rpName = n; }
    public String getOrigin()            { return origin; }
    public void setOrigin(String o)      { this.origin = o; }
}
