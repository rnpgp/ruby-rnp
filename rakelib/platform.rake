# frozen_string_literal: true

require "fileutils"
require "tmpdir"

require "rake/clean"
require "rubygems/package_task"

desc "Build install-compilation gem"
task "gem:native:any" do
  sh "rake platform:any gem"
end

desc "Define the gem task to build on any platform (compile on install)"
task "platform:any" do
  spec = Gem::Specification::load("rnp.gemspec").dup
  task = Gem::PackageTask.new(spec)
  task.define
end

platforms = [
  ["x86-mingw32", "i686-w64-mingw32", "librnp-0.dll"],
  ["x64-mingw32", "x86_64-w64-mingw32", "librnp-0.dll"],
  ["x86-linux", "i686-linux-gnu", "librnp-0.so"],
  ["x86_64-linux", "x86_64-linux-gnu", "librnp-0.so"],
  ["x86_64-darwin", "x86_64-darwin", "librnp.dylib"],
  ["arm64-darwin", "arm64-darwin", "librnp.dylib"],
]

workspace = File.dirname(File.dirname(__FILE__))
librnp_path = File.join(workspace, "tmp", "rnp")

platforms.each do |platform, host, lib|
  desc "Build pre-compiled gem for the #{platform} platform"
  task "gem:native:#{platform}" do
    sh "rake compile[#{host},#{lib}] platform:#{platform} gem"
  end

  desc "Define the gem task to build on the #{platform} platform (binary gem)"
  task "platform:#{platform}" do
    spec = Gem::Specification::load("rnp.gemspec").dup
    spec.platform = Gem::Platform.new(platform)
    spec.files += ["lib/rnp/ffi/#{lib}"]
    spec.extensions = []

    task = Gem::PackageTask.new(spec)
    task.define
  end
end

desc "Git clone rnp native library"
task :rnp_git, [:rev] do |_t, args|
  rev = args[:rev] || "master"
  unless Dir.exist?(librnp_path)
    system("git clone https://github.com/rnpgp/rnp.git -b #{rev} #{librnp_path}")
  end

  Dir.chdir(librnp_path) {
    system("git checkout #{rev}")
  }
end

desc "Compile binary for the target host"
task :compile, [:host, :lib] => [:rnp_git] do |_t, args|
  workspace = File.dirname(File.dirname(__FILE__))

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
      "SKIP_TESTS" => "1"
    }

    cache_path = File.join(workspace, "tmp", cache_dir)
    FileUtils.mkdir_p(cache_path)
    FileUtils.ln_s(cache_path, tmp)

    deps = "botan jsonc"
    Dir.chdir(librnp_path) {
      system(build_env, "ci/install_cacheable_dependencies.sh #{deps}")
      system(build_env, "ci/run.sh")
    }

    FileUtils.cp(File.join(rnp_install, "lib", args[:lib]), "lib/rnp/ffi/")
  end
end

CLEAN.include("lib/rnp/ffi/librnp-0.dll",
              "lib/rnp/ffi/librnp.dylib",
              "lib/rnp/ffi/librnp-0.so")