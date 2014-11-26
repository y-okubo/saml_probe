Rails.application.routes.draw do
  # get '/saml/index'     => 'saml#index'
  # get '/saml/init'      => 'saml#init'
  # post '/saml/consume'  => 'saml#consume'
  # get '/saml/metadata'  => 'saml#metadata'
  # delete '/saml/logout'    => 'saml#logout'

  root to: 'saml#show'

  resource :saml, only: [:metadata, :create, :new, :show, :destroy], controller: 'saml' do
    member do
      get :metadata
    end
  end
end
