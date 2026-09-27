class Iterm2Harness < Formula
  desc "Scoped, observable iTerm2 automation with local approval"
  homepage "https://github.com/nullifyr/iterm2-harness"
  # Development tap only: do not masquerade a moving main archive as a stable release.
  # A stable url + sha256 must be added after publishing an immutable release archive.
  head "https://github.com/nullifyr/iterm2-harness.git", branch: "main"
  license "Apache-2.0"
  depends_on :macos

  def install
    libexec.install "iterm2-harness.py", "iterm2_harness", "config.json", "install.sh"
    prefix.install "README.md", "SECURITY.md", "CHANGELOG.md"
    (bin/"iterm2-harness-install").write <<~SH
      #!/bin/bash
      exec "#{opt_prefix}/libexec/install.sh" --source "#{opt_prefix}/libexec/iterm2-harness.py" "$@"
    SH
    chmod 0755, bin/"iterm2-harness-install"
  end

  def post_install
    system bin/"iterm2-harness-install"
  end

  def caveats
    <<~EOS
      Run iTerm2 > Scripts > AutoLaunch > iterm2-harness.py.
      iTerm2's Python runtime must be Python 3.9 or newer.
      User configuration is preserved in ~/.iterm2-harness/config.json.
      This is a HEAD-only development formula, not a tagged stable release.
    EOS
  end

  test do
    assert_predicate libexec/"iterm2_harness/server.py", :exist?
    assert_predicate bin/"iterm2-harness-install", :executable?
  end
end
