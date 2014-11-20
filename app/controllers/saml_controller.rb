class SamlController < ApplicationController
  skip_before_action :verify_authenticity_token

  def init
    request = OneLogin::RubySaml::Authrequest.new
    redirect_to(request.create(saml_settings))
  end

  def consume
    response          = OneLogin::RubySaml::Response.new(params[:SAMLResponse])
    response.settings = saml_settings

    # We validate the SAML Response and check if the user already exists in the system

    if response.is_valid?
      # authorize_success, log the user
      # binding.pry
      session[:userid] = response.name_id
      session[:attributes] = response.attributes
    else
      render text: response.errors
    end
  end

  def metadata
    meta = OneLogin::RubySaml::Metadata.new
    render xml: meta.generate(saml_settings), content_type: 'application/samlmetadata+xml'
  end

  private

  def saml_settings
    settings = OneLogin::RubySaml::Settings.new

    # IdP Data
    # settings.idp_cert                       = "MIICizCCAfQCCQCY8tKaMc0BMjANBgkqhkiG9w0BAQUFADCBiTELMAkGA1UEBhMCTk8xEjAQBgNVBAgTCVRyb25kaGVpbTEQMA4GA1UEChMHVU5JTkVUVDEOMAwGA1UECxMFRmVpZGUxGTAXBgNVBAMTEG9wZW5pZHAuZmVpZGUubm8xKTAnBgkqhkiG9w0BCQEWGmFuZHJlYXMuc29sYmVyZ0B1bmluZXR0Lm5vMB4XDTA4MDUwODA5MjI0OFoXDTM1MDkyMzA5MjI0OFowgYkxCzAJBgNVBAYTAk5PMRIwEAYDVQQIEwlUcm9uZGhlaW0xEDAOBgNVBAoTB1VOSU5FVFQxDjAMBgNVBAsTBUZlaWRlMRkwFwYDVQQDExBvcGVuaWRwLmZlaWRlLm5vMSkwJwYJKoZIhvcNAQkBFhphbmRyZWFzLnNvbGJlcmdAdW5pbmV0dC5ubzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAt8jLoqI1VTlxAZ2axiDIThWcAOXdu8KkVUWaN/SooO9O0QQ7KRUjSGKN9JK65AFRDXQkWPAu4HlnO4noYlFSLnYyDxI66LCr71x4lgFJjqLeAvB/GqBqFfIZ3YK/NrhnUqFwZu63nLrZjcUZxNaPjOOSRSDaXpv1kb5k3jOiSGECAwEAATANBgkqhkiG9w0BAQUFAAOBgQBQYj4cAafWaYfjBU2zi1ElwStIaJ5nyp/s/8B8SAPK2T79McMyccP3wSW13LHkmM1jwKe3ACFXBvqGQN0IbcH49hu0FKhYFM/GPDJcIHFBsiyMBXChpye9vBaTNEBCtU3KjjyG0hRT2mAQ9h+bkPmOvlEo/aH0xR68Z9hw4PF13w=="
    # settings.idp_entity_id
    settings.idp_sso_target_url   = "https://openidp.feide.no/simplesaml/saml2/idp/SSOService.php"
    settings.idp_slo_target_url   = "https://openidp.feide.no/simplesaml/saml2/idp/SingleLogoutService.php"
    settings.idp_cert_fingerprint = "C9:ED:4D:FB:07:CA:F1:3F:C2:1E:0F:EC:15:72:04:7E:B8:A7:A4:CB"

    # SP Data
    settings.assertion_consumer_service_url     = "http://sso.y-okubo.com:3000/saml/consume"
    settings.issuer                             = "http://sso.y-okubo.com:3000"
    settings.name_identifier_format             = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

    settings.private_key = "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAqo7yzr9U5ySlyTW4Ec7QLvzboZPA0iygV3LmG/1OYT4NhOOg
nZRUs/XJsWQ/SEg2tgCIEMUhA9HoGPFswI8phG9Lhb3vaGzQsofo6WYsH7NGhm4W
kBMcvddS37AmWzHYYJg2GAN2Ff7ciaRpt0wyCtJ2Gl/J8dYq6RaA21GBdKOsWvS4
E1iFOk/+cqfRyJ5f4j6H+AToc5OLrql6p3FtO9UFIp3W5OfiOK7KVceJUzt0xYFn
vXQbHDGvER0qXA/eMKlLiD6MCkUxTUeDk31Qq3nlQgi3OB1YSMotdKe/Ns0UkZ9h
1EA5LgPy5guCR5dwZTPeFskNZw5sg2qVIbcpsQIDAQABAoIBAAcned3cPrZ3XhDj
lPYCQ89Ewf20Eel+/7bLVgWkiW4gyTZiyfDyMN9flvc+6jyg8tKNkSeK7UiYvHCX
Z+Vn2+j3NibFAc7SiaqDcuyfYYhu361x3rZqZtE7v/ksDV/T5mye1d4J/yELELsh
T2Hl609y5otSq0jen+wpCnyonZKD3YXgF7SGLZ6BliK2EMSCiG7Wi/3/0eDCt8DQ
sHXaRV67d77pPVam4YiEiAZmrN44b/gTR+Yj60VLhUtAUO2hokAnnWGvxUuYRL0n
/z+rSqc+RD141papuywwAZciHu82ndV7/kapqZfXooBsNoJeDXcrLDMVsSB95jn3
IkrNRZUCgYEA07Y4uJokyKZlnMHglre91AHyxGRY6SHW2paSGMoOytlxjSG9XX47
t7agJDYnDXti0yBoGhkeM8MQ/v1HisBfbkusFMo8gAkLKdMiehkcuVIgcXSM4PNu
KnHwZp4CwBjUM3Q0AI58NwcFSX7b+7jfeeLdAI7LosdoIxZoAPKEPYcCgYEAzjzX
ycaxWT44u58Q2QuKgSHbkH5dIdCEfVw3q8FhN3oOrkKH+4GohFYYp+YyYp21OfMF
YIHNn7ccKbg8aqADg++eLTcmLlVzvEkvhbzRbawlEjt08KtHLIsHzRCYU0VQCixt
uvvUj4/VAL+uRlcp9pTno9zuB/zFml0lMoChbQcCgYAd/b5jSFLVqdzTLBPoxfa6
RdxiPeTqgcSyCop/wH//9HXFjHYK/IrxJ4ngF1vI6SXCyuB0cgJ5SrTpqm+sFDxw
n3+tIkkXyjAuqJ5FtbD//8ZgzCX46AM/OAzaPKAfHmVRNLD5MzYdhX0WQEZhjnr6
BU1ReukWEjGKZu4s1C4vmQKBgHozMuksAgmPBK6nIaR5YigBl8eWGDjhBKAC9Dmg
66mjeO9oHIq52NAQ86sIivJD4A3mIVl9kAkCxn0x3RqQlYSnhmHkO4tYtqrp8m6b
4rvJNG4JLNEtq46JEqY/HwK4HyToDlysutYVs3AuI2UqYILq2BYP4jp5W9yLNG8o
KH4hAoGBAJGdJBUAAfCkukftgkMIm+MXz2NRzg7013HQ5XBt5Gi1QLR0ZmYO67As
CihXf62zksY7ZwuWMFX7jWA8EwSwng2uu67g7/rJV9A8lnd34ZVmEkZ/DxaI7f71
LLQ670n+aOgvv35VyLv4NndpzwsaDxlkMSe3/pgw0iH8urOBdo80
-----END RSA PRIVATE KEY-----"


    settings.certificate = "-----BEGIN CERTIFICATE-----
MIIDADCCAegCCQCCzikpfqUFxjANBgkqhkiG9w0BAQUFADBCMQswCQYDVQQGEwJY
WDEVMBMGA1UEBwwMRGVmYXVsdCBDaXR5MRwwGgYDVQQKDBNEZWZhdWx0IENvbXBh
bnkgTHRkMB4XDTE0MTExMzA5MTkzMFoXDTI0MTExMDA5MTkzMFowQjELMAkGA1UE
BhMCWFgxFTATBgNVBAcMDERlZmF1bHQgQ2l0eTEcMBoGA1UECgwTRGVmYXVsdCBD
b21wYW55IEx0ZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKqO8s6/
VOckpck1uBHO0C7826GTwNIsoFdy5hv9TmE+DYTjoJ2UVLP1ybFkP0hINrYAiBDF
IQPR6BjxbMCPKYRvS4W972hs0LKH6OlmLB+zRoZuFpATHL3XUt+wJlsx2GCYNhgD
dhX+3ImkabdMMgrSdhpfyfHWKukWgNtRgXSjrFr0uBNYhTpP/nKn0cieX+I+h/gE
6HOTi66peqdxbTvVBSKd1uTn4jiuylXHiVM7dMWBZ710GxwxrxEdKlwP3jCpS4g+
jApFMU1Hg5N9UKt55UIItzgdWEjKLXSnvzbNFJGfYdRAOS4D8uYLgkeXcGUz3hbJ
DWcObINqlSG3KbECAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAjKRm61mf4Xj9/FZO
lksomBQflvSQBKmyTVQggLrCxOgqSEJ3WfAZIihGqpa04/vqVscENPzJbX3V24oq
kXhfLcfAGrZYN+Kd7SPuU9Ec7HU0Is2rK3zuWu+sybR19Dbc0ZEhJkY8F/z3k7bH
YYqHxl0etMRPGUZRnjhS2FCh85rSdtRSCvYEbSwGfqJnB6PZgMBqlbAMJRRTn5os
UNGfABuwswFtLU8R3V/JmXcM5TBNcJaS0MtBLhiNnFh4acRk38FvD9EPeqT9jaT3
Xdjt0LPSkCogaErXx6gkxDnazPCnv/gbJxE1tq5tupRflnQ6vasds01xkG7gbaBF
n0vrdw==
-----END CERTIFICATE-----"

    settings.security[:authn_requests_signed]   = true     # Enable or not signature on AuthNRequest
    settings.security[:logout_requests_signed]  = true     # Enable or not signature on Logout Request
    settings.security[:logout_responses_signed] = true     # Enable or not signature on Logout Response
    settings.security[:digest_method]           = XMLSecurity::Document::SHA1
    settings.security[:signature_method]        = XMLSecurity::Document::SHA1
    settings.security[:embed_sign]              = false

    # Optional for most SAML IdPs
    settings.authn_context = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

    # Optional. Describe according to IdP specification (if supported) which attributes the SP desires to receive in SAMLResponse.
    # settings.attributes_index = 5
    # Optional. Describe an attribute consuming service for support of additional attributes.
    # settings.attribute_consuming_service.configure do
    #   service_name "Service"
    #   service_index 5
    #   add_attribute :name => "Name", :name_format => "Name Format", :friendly_name => "Friendly Name"
    # end

    settings
  end
end
