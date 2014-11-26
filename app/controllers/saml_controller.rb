class SamlController < ApplicationController
  skip_before_action :verify_authenticity_token

  def init
    request = OneLogin::RubySaml::Authrequest.new
    redirect_to(request.create(saml_settings))
  end

  def consume
    response          = OneLogin::RubySaml::Response.new(params[:SAMLResponse])
    response.settings = saml_settings

    if response.is_valid?
      session[:userid] = response.name_id
      session[:attributes] = response.attributes["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"]
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

    # IdP configuration
    idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
    settings = idp_metadata_parser.parse_remote('https://login.windows.net/b4c126ab-dde9-4d6c-8f38-2fad2717aad4/federationmetadata/2007-06/federationmetadata.xml')

    # SP configuration
    settings.assertion_consumer_service_url     = "http://localhost:3000/saml/consume"
    settings.issuer                             = "http://localhost:3000"
    settings.name_identifier_format             = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

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
