require "support/shared/integration/integration_helper"
require "chef/mixin/shell_out"
require "chef/run_lock"
require "chef/config"
require "timeout"
require "fileutils"

describe "chef-solo" do
  include IntegrationSupport
  include Chef::Mixin::ShellOut

  let(:chef_dir) { File.join(File.dirname(__FILE__), "..", "..", "..") }

  let(:cookbook_x_100_metadata_rb) { cb_metadata("x", "1.0.0") }

  let(:cookbook_ancient_100_metadata_rb) { cb_metadata("ancient", "1.0.0") }

  let(:chef_solo) { "ruby bin/chef-solo --legacy-mode --minimal-ohai" }

  when_the_repository "has a cookbook with a basic recipe" do
    before do
      file "cookbooks/x/metadata.rb", cookbook_x_100_metadata_rb
      file "cookbooks/x/recipes/default.rb", 'puts "ITWORKS"'
    end

    it "should complete with success" do
      file "config/solo.rb", <<EOM
cookbook_path "#{path_to('cookbooks')}"
file_cache_path "#{path_to('config/cache')}"
EOM
      result = shell_out("#{chef_solo} -c \"#{path_to('config/solo.rb')}\" -o 'x::default' -l debug", :cwd => chef_dir)
      result.error!
      expect(result.stdout).to include("ITWORKS")
    end

    it "should evaluate its node.json file" do
      file "config/solo.rb", <<EOM
cookbook_path "#{path_to('cookbooks')}"
file_cache_path "#{path_to('config/cache')}"
EOM

      file "config/node.json", <<-E
{"run_list":["x::default"]}
E

      result = shell_out("#{chef_solo} -c \"#{path_to('config/solo.rb')}\" -j '#{path_to('config/node.json')}' -l debug", :cwd => chef_dir)
      result.error!
      expect(result.stdout).to include("ITWORKS")
    end

  end

  when_the_repository "has a cookbook with an undeclared dependency" do
    before do
      file "cookbooks/x/metadata.rb", cookbook_x_100_metadata_rb
      file "cookbooks/x/recipes/default.rb", 'include_recipe "ancient::aliens"'

      file "cookbooks/ancient/metadata.rb", cookbook_ancient_100_metadata_rb
      file "cookbooks/ancient/recipes/aliens.rb", 'print "it was aliens"'
    end

    it "should exit with an error" do
      file "config/solo.rb", <<EOM
cookbook_path "#{path_to('cookbooks')}"
file_cache_path "#{path_to('config/cache')}"
EOM
      result = shell_out("#{chef_solo} -c \"#{path_to('config/solo.rb')}\" -o 'x::default' -l debug", :cwd => chef_dir)
      expect(result.exitstatus).to eq(0) # For CHEF-5120 this becomes 1
      expect(result.stdout).to include("WARN: MissingCookbookDependency")
    end
  end

  when_the_repository "has a cookbook with an incompatible chef_version" do
    before do
      file "cookbooks/x/metadata.rb", cb_metadata("x", "1.0.0", "\nchef_version '~> 999.0'")
      file "cookbooks/x/recipes/default.rb", 'puts "ITWORKS"'
      file "config/solo.rb", <<EOM
cookbook_path "#{path_to('cookbooks')}"
file_cache_path "#{path_to('config/cache')}"
EOM
    end

    it "should exit with an error" do
      result = shell_out("#{chef_solo} -c \"#{path_to('config/solo.rb')}\" -o 'x::default' -l debug", :cwd => chef_dir)
      expect(result.exitstatus).to eq(1)
      expect(result.stdout).to include("Chef::Exceptions::CookbookChefVersionMismatch")
    end
  end

  when_the_repository "has a cookbook with an incompatible ohai_version" do
    before do
      file "cookbooks/x/metadata.rb", cb_metadata("x", "1.0.0", "\nohai_version '~> 999.0'")
      file "cookbooks/x/recipes/default.rb", 'puts "ITWORKS"'
      file "config/solo.rb", <<EOM
cookbook_path "#{path_to('cookbooks')}"
file_cache_path "#{path_to('config/cache')}"
EOM
    end

    it "should exit with an error" do
      result = shell_out("#{chef_solo} -c \"#{path_to('config/solo.rb')}\" -o 'x::default' -l debug", :cwd => chef_dir)
      expect(result.exitstatus).to eq(1)
      expect(result.stdout).to include("Chef::Exceptions::CookbookOhaiVersionMismatch")
    end
  end

  when_the_repository "has a cookbook with a recipe with sleep" do
    before do
      directory "logs"
      file "logs/runs.log", ""
      file "cookbooks/x/metadata.rb", cookbook_x_100_metadata_rb
      file "cookbooks/x/recipes/default.rb", <<EOM
ruby_block "sleeping" do
  block do
    retries = 200000
    while IO.read(Chef::Config[:log_location]) !~ /Chef client .* is running, will wait for it to finish and then run./
      sleep 0.1
      raise "we ran out of retries" if ( retries -= 1 ) <= 0
    end
  end
end
EOM
    end

    it "while running solo concurrently" do
      file "config/solo.rb", <<EOM
cookbook_path "#{path_to('cookbooks')}"
file_cache_path "#{path_to('config/cache')}"
EOM
      # We have a timeout protection here so that if due to some bug
      # run_lock gets stuck we can discover it.
      expect do
        Timeout.timeout(120) do
          chef_dir = File.join(File.dirname(__FILE__), "..", "..", "..")

          threads = []

          # Instantiate the first chef-solo run
          threads << Thread.new do
            s1 = Process.spawn("#{chef_solo} -c \"#{path_to('config/solo.rb')}\" -o 'x::default'  -l debug -L #{path_to('logs/runs.log')}", :chdir => chef_dir)
            puts "before waitpid1"
            Process.waitpid(s1)
            puts "after waitpid1"
          end

          # Instantiate the second chef-solo run
          threads << Thread.new do
            s2 = Process.spawn("#{chef_solo} -c \"#{path_to('config/solo.rb')}\" -o 'x::default'  -l debug -L #{path_to('logs/runs.log')}", :chdir => chef_dir)
            puts "before waitpid2"
            Process.waitpid(s2)
            puts "after waitpid2"
          end

          threads.each(&:join)
        end
      end.not_to raise_error

      # Unfortunately file / directory helpers in integration tests
      # are implemented using before(:each) so we need to do all below
      # checks in one example.
      run_log = File.read(path_to("logs/runs.log"))

      # second run should have a message which indicates it's waiting for the first run
      expect(run_log).to match(/Chef client .* is running, will wait for it to finish and then run./)

      # both of the runs should succeed
      expect(run_log.lines.reject { |l| !l.include? "INFO: Chef Run complete in" }.length).to eq(2)
    end

  end
end
