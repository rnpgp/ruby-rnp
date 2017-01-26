require 'rubygems'
require 'rake'
require 'rspec/core/rake_task'

desc 'Run rspec'

RSpec::Core::RakeTask.new do |t|
  t.verbose = true
end

desc 'Run specs'
task :spec_all do
  system 'rake spec'
end

task :default => :spec

