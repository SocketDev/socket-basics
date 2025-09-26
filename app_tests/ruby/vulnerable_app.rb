# Vulnerable Ruby application for testing
require 'sqlite3'
require 'erb'

class VulnerableApp
  def initialize
    @db = SQLite3::Database.new "example.db"
  end
  
  def search_user(user_input)
    # SQL injection vulnerability
    query = "SELECT * FROM users WHERE name = '#{user_input}'"
    @db.execute(query)
    
    # Command injection vulnerability
    system("ls -la #{user_input}")
    
    # ERB template injection
    template = ERB.new("<%= #{user_input} %>")
    template.result(binding)
  end
  
  def authenticate
    # Hardcoded secret
    secret_key = "super_secret_rails_key"
    
    # Weak random
    session_token = rand(1000000).to_s
    
    # Mass assignment vulnerability
    user_params = params.permit!
    User.create(user_params)
    
    # Open redirect
    redirect_to params[:redirect_url]
  end
  
  def unsafe_yaml_load(user_data)
    # Unsafe deserialization
    YAML.load(user_data)
  end
  
  def disable_csrf_protection
    # CSRF protection disabled
    skip_before_action :verify_authenticity_token
  end
end

# File operations
user_input = gets.chomp
filename = "/tmp/#{user_input}.txt"
File.open(filename, 'w') { |f| f.write("data") }
