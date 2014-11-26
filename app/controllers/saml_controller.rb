class SamlController < ApplicationController
  skip_before_action :verify_authenticity_token

  def new
    request = OneLogin::RubySaml::Authrequest.new
    redirect_to(request.create(saml_settings))
  end

  def create
    response          = OneLogin::RubySaml::Response.new(params[:SAMLResponse])
    response.settings = saml_settings

    if response.is_valid?
      session[:userid] = response.name_id
      session[:attributes] = response.attributes["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"]
    else
      render text: response.errors
    end
  end

  def destroy
    # If we're given a logout request, handle it in the IdP logout initiated method
    if params[:SAMLRequest]
      return idp_logout_request
    # We've been given a response back from the IdP, process it
    elsif params[:SAMLResponse]
      return process_logout_response
    # Initiate SLO (send Logout Request)
    else
      return sp_logout_request
    end
  end

  def metadata
    meta = OneLogin::RubySaml::Metadata.new
    render xml: meta.generate(saml_settings), content_type: 'application/samlmetadata+xml'
  end

  private

  # Create a SP initiated SLO
  def sp_logout_request
    # LogoutRequest accepts plain browser requests w/o paramters
    settings = saml_settings

    if settings.idp_slo_target_url.nil?
      logger.info "SLO IdP Endpoint not found in settings, executing then a normal logout'"
      delete_session
    else

      # Since we created a new SAML request, save the transaction_id
      # to compare it with the response we get back
      logout_request = OneLogin::RubySaml::Logoutrequest.new()
      session[:transaction_id] = logout_request.uuid
      logger.info "New SP SLO for userid '#{session[:userid]}' transactionid '#{session[:transaction_id]}'"

      if settings.name_identifier_value.nil?
        settings.name_identifier_value = session[:userid]
      end

      relay_state =  url_for controller: 'saml', action: 'show'
      redirect_to(logout_request.create(settings, RelayState: relay_state))
    end
  end

  def process_logout_response
    settings = Account.get_saml_settings

    if session.has_key? :transation_id
      logout_response = OneLogin::RubySaml::Logoutresponse.new(params[:SAMLResponse], settings, :matches_request_id => session[:transation_id])
    else
      logout_response = OneLogin::RubySaml::Logoutresponse.new(params[:SAMLResponse], settings)
    end

    logger.info "LogoutResponse is: #{logout_response.to_s}"

    # Validate the SAML Logout Response
    if not logout_response.validate
      logger.error "The SAML Logout Response is invalid"
    else
      # Actually log out this session
      if logout_response.success?
        logger.info "Delete session for '#{session[:userid]}'"
        delete_session
      end
    end
  end

  # Delete a user's session.
  def delete_session
    session[:userid] = nil
    session[:attributes] = nil
  end

  def saml_settings
    settings = OneLogin::RubySaml::Settings.new

    # IdP configuration
    idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
    settings = idp_metadata_parser.parse_remote('https://login.windows.net/b4c126ab-dde9-4d6c-8f38-2fad2717aad4/federationmetadata/2007-06/federationmetadata.xml')

    # SP configuration
    settings.assertion_consumer_service_url     = "http://localhost:3000/saml"
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
