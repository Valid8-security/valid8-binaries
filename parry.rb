# Homebrew Formula for Parry Security Scanner
class Parry < Formula
  include Language::Python::Virtualenv

  desc "Privacy-first AI-powered security scanner with local LLM"
  homepage "https://github.com/parry-security/parry"
  url "https://github.com/parry-security/parry/archive/v0.1.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "MIT"

  depends_on "python@3.11"
  depends_on "ollama"

  resource "click" do
    url "https://files.pythonhosted.org/packages/click-8.1.7.tar.gz"
    sha256 "..."
  end

  resource "rich" do
    url "https://files.pythonhosted.org/packages/rich-13.7.0.tar.gz"
    sha256 "..."
  end

  resource "requests" do
    url "https://files.pythonhosted.org/packages/requests-2.31.0.tar.gz"
    sha256 "..."
  end

  def install
    virtualenv_install_with_resources
    
    # Install Ollama model
    system "ollama", "pull", "codellama:7b-instruct"
  end

  def post_install
    # Verify installation
    system bin/"parry", "doctor"
  end

  test do
    system "#{bin}/parry", "--version"
    system "#{bin}/parry", "doctor"
  end
end


