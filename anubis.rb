# Anubis — Homebrew Formula
# Install: brew install --HEAD anubis.rb
# Or tap: brew tap SepJs/anubis

class Anubis < Formula
  desc "Advanced modular security scanner with AI-driven heuristics and polymorphic evasion"
  homepage "https://github.com/SepJs/anubis"
  url "https://github.com/SepJs/anubis/archive/refs/tags/v2.0.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000" # Set on release
  license "MIT"
  head "https://github.com/SepJs/anubis.git", branch: "main"

  depends_on "go" => :build

  def install
    ENV["CGO_ENABLED"] = "0"

    ldflags = %W[
      -s -w
      -X github.com/SepJs/anubis/pkg/version.Version=#{version}
      -X github.com/SepJs/anubis/pkg/version.BuildDate=#{time.iso8601}
      -X github.com/SepJs/anubis/pkg/version.GitHash=#{Utils.git_head}
    ]

    system "go", "build",
      "-trimpath",
      "-buildmode=pie",
      "-ldflags", ldflags.join(" "),
      "-o", bin/"anubis",
      "./cmd/anubis"

    # Man page
    man1.install "docs/man/anubis.1" if File.exist?("docs/man/anubis.1")

    # Shell completions
    bash_completion.install "completions/anubis.bash" if File.exist?("completions/anubis.bash")
    zsh_completion.install "completions/anubis.zsh" if File.exist?("completions/anubis.zsh")
    fish_completion.install "completions/anubis.fish" if File.exist?("completions/anubis.fish")
  end

  def caveats
    <<~EOS
      Anubis v#{version} installed.

      Quick start:
        anubis -t https://example.com -l 1

      For stealth mode:
        anubis -t https://example.com -l 1 --ghost --strategy polymorphic

      Documentation:
        man anubis
        https://github.com/SepJs/anubis

      IMPORTANT: Authorized use only. Scanning systems without permission is illegal.
    EOS
  end

  test do
    assert_match "Anubis", shell_output("#{bin}/anubis --version")
    assert_match "v#{version}", shell_output("#{bin}/anubis --version")
  end
end
