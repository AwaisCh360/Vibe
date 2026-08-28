require 'sinatra'
set :session_secret, 'super_secret_key_123'

get '/run' do
  cmd = params[:cmd]
  `#{cmd}` # Command injection
end
