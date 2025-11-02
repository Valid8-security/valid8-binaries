# Ruby test file with intentional vulnerabilities

require 'digest'

class VulnerableApp
  # CWE-78: Command Injection
  def execute_command(user_input)
    system("ls -la #{user_input}")
  end
  
  # CWE-89: SQL Injection
  def query_user(username)
    query = "SELECT * FROM users WHERE name = '#{params[:username]}'"
    User.where(query)
  end
  
  # CWE-79: XSS
  def display_greeting(name)
    render inline: "<h1>Hello, #{name}</h1>".html_safe
  end
  
  # CWE-327: Weak Crypto
  def hash_password(password)
    Digest::MD5.hexdigest(password)
  end
  
  # CWE-798: Hardcoded Credentials
  def connect_database
    password = "SuperSecret123"
    api_key = "sk_live_1234567890"
    # Use credentials
  end
  
  # CWE-502: Unsafe Deserialization
  def deserialize_data(data)
    Marshal.load(data)
  end
  
  # CWE-1321: Mass Assignment
  def create_user
    User.create(params[:user])
  end
end


