# frozen_string_literal: true

require "fileutils"
require "rbconfig"
require "tmpdir"

require "rake/clean"
require "rubygems/package_task"

def libname
  case RbConfig::CONFIG["host_os"]
  when /mswin|windows/i
    "librnp.dll"
  when /linux|arch/i
    "librnp.so"
  when /darwin/i
    "librnp.dylib"
  else
    raise RuntimeError "Unsupported Host OS"
  end
end

# rnp moved its CI shell scripts from ci/ to ci-legacy/ without updating
# their internal references, which still expect to be sourced as ci/...
# from the repository root. Recreate the expected layout with symlinks.
def setup_legacy_ci_scripts
  {
    "ci/main.sh" => "../ci-legacy/main.sh",
    "ci/success.sh" => "../ci-legacy/success.sh",
    "ci/env.inc.sh" => "../ci-legacy/env.inc.sh",
    "ci/env-common.inc.sh" => "../ci-legacy/env-common.inc.sh",
    "ci/env-linux.inc.sh" => "../ci-legacy/env-linux.inc.sh",
    "ci/env-freebsd.inc.sh" => "../ci-legacy/env-freebsd.inc.sh",
    "ci/utils.inc.sh" => "../ci-legacy/utils.inc.sh",
    "ci/lib/install_functions.inc.sh" =>
      "../../ci-legacy/lib/install_functions.inc.sh",
    "ci/lib/cacheable_install_functions.inc.sh" =>
      "../../ci-legacy/lib/cacheable_install_functions.inc.sh",
  }.each do |link, target|
    next if File.exist?(link)
    FileUtils.mkdir_p(File.dirname(link))
    FileUtils.ln_s(target, link)
  end
end

workspace = File.dirname(File.dirname(__FILE__))
librnp_path = File.join(workspace, "tmp", "rnp")

desc "Build install-compilation gem"
task "gem:native:any" do
  sh "rake platform:any gem"
end

desc "Build install-compilation gem"
task "gem:native" do
  sh "rake platform:native gem"
end

desc "Define the gem task to build on any platform (compile on install)"
task "platform:any" do
  spec = Gem::Specification::load("rnp.gemspec").dup
  task = Gem::PackageTask.new(spec)
  task.define
end

desc "Define the gem task to build the platform gem (binary gem)"
task "platform:native" => [:compile] do
  platform = Gem::Platform.new(RUBY_PLATFORM)
  platform.version = nil
  spec = Gem::Specification::load("rnp.gemspec").dup
  spec.platform = platform
  spec.files += ["lib/rnp/ffi/#{libname}"]
  spec.extensions = []

  task = Gem::PackageTask.new(spec)
  task.define
end

desc "Git clone rnp native library"
task :rnp_git do
  rev = ENV["RNP_VERSION"] || "main"
  unless Dir.exist?(librnp_path)
    system("git clone https://github.com/rnpgp/rnp -b #{rev} #{librnp_path}")
  end

  Dir.chdir(librnp_path) { system("git checkout #{rev}") }
end

desc "Compile binary"
task compile: [:rnp_git] do
  Dir.mktmpdir do |tmp|
    cache_dir = "installs"
    rnp_install = File.join(workspace, "tmp", "rnp-install")

    build_env = {
      "LOCAL_BUILDS" => File.join(workspace, "tmp", "builds"),
      "CACHE_DIR" => cache_dir,
      "LOCAL_INSTALLS" => tmp,
      "BOTAN_INSTALL" => File.join(tmp, "botan-install"),
      "JSONC_INSTALL" => File.join(tmp, "jsonc-install"),
      "RNP_INSTALL" => rnp_install,
      "USE_STATIC_DEPENDENCIES" => "yes",
      "SKIP_TESTS" => "1",
    }

    cache_path = File.join(workspace, "tmp", cache_dir)
    FileUtils.mkdir_p(cache_path)
    FileUtils.ln_s(cache_path, tmp)

    Dir.chdir(librnp_path) do
      ci_dir = Dir.exist?("ci-legacy") ? "ci-legacy" : "ci"
      setup_legacy_ci_scripts if ci_dir == "ci-legacy"

      system(build_env, "#{ci_dir}/install_noncacheable_dependencies.sh")
      system(build_env, "#{ci_dir}/install_cacheable_dependencies.sh botan jsonc")
      system(build_env, "#{ci_dir}/run.sh")
    end

    FileUtils.cp(File.join(rnp_install, "lib", libname), "lib/rnp/ffi/")
  end
end

CLOBBER.include("pkg")
CLEAN.include("lib/rnp/ffi/#{libname}")
