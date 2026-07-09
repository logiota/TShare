# Homebrew formula for tshare.
#
# Local install (from this repo):
#   brew install --build-from-source ./Formula/tshare.rb
#
# For a tap, push tshare to a GitHub repo, cut a release tarball, set `url`
# and `sha256` below, then:  brew tap <you>/tshare && brew install tshare
class Tshare < Formula
  desc "Secret-link file sharing & collaboration over Tailscale Funnel"
  homepage "https://github.com/yourname/tshare"
  version "1.5.0"
  license "MIT"

  # Replace with your release tarball + checksum (shasum -a 256 tshare-1.5.0.tar.gz):
  url "https://github.com/yourname/tshare/archive/refs/tags/v1.5.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"

  depends_on "go" => :build

  # Optional runtime helpers (not required to install):
  #   tailscale  — required at runtime for funnel/serve (install separately)
  #   yt-dlp     — URL/video sharing       (brew install yt-dlp)
  #   ffmpeg     — --transcode / --hevc    (brew install ffmpeg)
  #   qrencode   — terminal QR codes       (brew install qrencode)

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w"), "."
  end

  # `brew services start tshare` restarts every share saved with --persist at
  # login (same as `tshare resume`, and the same thing `tshare agent install`
  # sets up as a plain LaunchAgent). run_type :immediate = run once at load/boot.
  service do
    run [opt_bin/"tshare", "resume"]
    run_type :immediate
    keep_alive false
    log_path var/"log/tshare.log"
    error_log_path var/"log/tshare.log"
    environment_variables PATH: std_service_path_env
  end

  test do
    assert_match "tshare v#{version}", shell_output("#{bin}/tshare version")
  end
end
