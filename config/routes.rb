Rails.application.routes.draw do
  get '/saml/init'      => 'saml#init'
  post '/saml/consume'  => 'saml#consume'
  get '/saml/metadata'  => 'saml#metadata'

  root to: 'saml#init'
end
