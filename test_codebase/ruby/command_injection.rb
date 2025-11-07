def run_cmd(cmd)
  # CWE-78: Command Injection
  system("ls #{cmd}")
end