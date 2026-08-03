# The formula published to the hunterh37/homebrew-tap repository at release
# time.
#
#   brew install hunterh37/tap/wealdrelay
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
# Status: the tap does not exist until the first signed release is tagged, and
# neither do the tarballs this formula points at. The placeholder version and
# checksums below are what an unreleased formula looks like.
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

  # The relay reads `relay.toml` from its working directory and from nowhere
  # else, so the config file has to live where the service runs rather than
  # under etc. That directory is created here, with a commented-out starter file
  # in it, so the caveat below can name a path that exists.
  def install
    bin.install "wealdrelay"
    (var/"wealdrelay/blobs").mkpath
    config = var/"wealdrelay/relay.toml"
    config.write <<~TOML unless config.exist?
      # wealdrelay configuration. Read from the working directory of the running
      # relay, which for `brew services` is the directory holding this file.
      #
      # Keys are the environment variable names without the WEALD_RELAY_ prefix,
      # lowercased, under [relay]. An environment variable wins over this file,
      # and a key the relay does not recognise is an error rather than a shrug.
      #
      # Uncomment and fill in the two that have no default. Storage already
      # points at ./blobs beside this file.

      [relay]
      # hostname = "relay.example.com"
      # database_url = "postgres://wealdrelay:PASSWORD@127.0.0.1:5432/wealdrelay"
    TOML
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
      Two of the three required settings have no default. Put them in

        #{var}/wealdrelay/relay.toml

      which is where this formula wrote a starter file. The relay reads
      relay.toml from its working directory and from nowhere else, and this
      formula's service runs in #{var}/wealdrelay, so that path is the config
      file and any other location is read by nothing.

        [relay]
        hostname = "relay.example.com"
        database_url = "postgres://wealdrelay:PASSWORD@127.0.0.1:5432/wealdrelay"

      storage_url already defaults to #{var}/wealdrelay/blobs through the
      service's environment. Environment variables of the same name with a
      WEALD_RELAY_ prefix override the file, which is the route to use if you
      run the binary by hand from some other directory.

      Then:

        brew services start wealdrelay
        wealdrelay --check-config      # from #{var}/wealdrelay

      The first run prints a one-time enrollment URL and a one-time code. The
      URL is reprinted on every start while the workspace is still unenrolled.
      The code is not, ever: the relay keeps only its hash, so there is nothing
      left to print. Lose the code before a device enrols and the only way
      forward is an empty database.
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
