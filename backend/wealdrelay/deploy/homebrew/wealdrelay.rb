# The formula published to the weald/homebrew-tap repository at release time.
#
#   brew install weald/tap/wealdrelay
#
# specs/backend/relay/server.md distribution channel 4: for local development,
# and for a team that genuinely wants to run this on a Mac mini in a cupboard,
# which at this posture is a legitimate deployment.
#
# A bottle is deliberately not built. The release already produces signed static
# binaries for these targets and their SHA-256 is published; pointing the formula
# at those artifacts means the thing Homebrew installs is byte-identical to the
# thing the release notes name, which is the whole of
# specs/backend/relay/verification.md proof 2. A bottle would be a fifth artifact
# nobody verified.
#
# The version, the URLs and the four sha256 values below are rewritten by
# scripts/release-homebrew.sh from the release manifest. Editing them by hand is
# how the tap and the release stop agreeing.
class Wealdrelay < Formula
  desc "Weald blind relay. Stores and forwards envelopes it cannot read"
  homepage "https://github.com/hunterh37/WealdRelay"
  version "0.0.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/hunterh37/WealdRelay/releases/download/wealdrelay-v0.0.0/wealdrelay-aarch64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
    on_intel do
      # x86_64-apple-darwin is not one of the four targets in
      # specs/backend/relay/server.md. An Intel Mac runs the arm64 build under
      # Rosetta 2 or uses the container image; Homebrew is told so rather than
      # offered a binary that does not exist.
      odie "wealdrelay ships no x86_64 macOS binary. Use the container image, " \
           "or run the arm64 build under Rosetta 2."
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/hunterh37/WealdRelay/releases/download/wealdrelay-v0.0.0/wealdrelay-aarch64-unknown-linux-musl.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
    on_intel do
      url "https://github.com/hunterh37/WealdRelay/releases/download/wealdrelay-v0.0.0/wealdrelay-x86_64-unknown-linux-musl.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  # Postgres is the one dependency the relay cannot do without. Object storage
  # falls back to a directory and Redis is only needed for multi-process fanout,
  # so neither is a formula dependency.
  depends_on "postgresql@16"

  def install
    bin.install "wealdrelay"
    (etc/"wealdrelay").install "relay.toml.example" if File.exist?("relay.toml.example")
  end

  service do
    run [opt_bin/"wealdrelay"]
    keep_alive true
    working_dir var/"wealdrelay"
    log_path var/"log/wealdrelay.log"
    error_log_path var/"log/wealdrelay.log"
    environment_variables WEALD_RELAY_STORAGE_URL: "file://#{HOMEBREW_PREFIX}/var/wealdrelay/blobs"
  end

  def caveats
    <<~EOS
      Set the three required variables before starting the service:

        WEALD_RELAY_HOSTNAME
        WEALD_RELAY_DATABASE_URL
        WEALD_RELAY_STORAGE_URL

      or put them in #{etc}/wealdrelay/relay.toml. Then:

        brew services start wealdrelay

      The first run prints a one-time enrollment URL. It expires in 24 hours or
      on first use, and the first device to open it becomes the workspace trust
      root.
    EOS
  end

  test do
    # The binary reports its own identity, and refuses to serve without a
    # configuration while naming the variable that is missing. Both are
    # properties the release depends on, so they are the smoke test.
    assert_match "wealdrelay #{version}", shell_output("#{bin}/wealdrelay --version")
    output = shell_output("#{bin}/wealdrelay --check-config 2>&1", 78)
    assert_match "WEALD_RELAY_HOSTNAME", output
  end
end
