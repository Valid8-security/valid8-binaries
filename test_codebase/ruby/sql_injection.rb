require 'sqlite3'

def get_user(username)
  db = SQLite3::Database.new 'test.db'
  # CWE-89: SQL Injection
  query = "SELECT * FROM users WHERE name = '#{username}'"
  db.execute(query)
end