require "support/shared/integration/integration_helper"
require "chef/mixin/shell_out"
require "chef/run_lock"
require "chef/config"
require "timeout"
require "fileutils"
require "chef/win32/security" if Chef::Platform.windows?
require "chef/dist"

describe Chef::Dist::SOLOEXEC do
  include IntegrationSupport
  include Chef::Mixin::ShellOut

  let(:chef_dir) { File.join(File.dirname(__FILE__), "..", "..", "..") }

  let(:cookbook_x_100_metadata_rb) { cb_metadata("x", "1.0.0") }

  let(:cookbook_ancient_100_metadata_rb) { cb_metadata("ancient", "1.0.0") }

  let(:chef_solo) { "bundle exec #{Chef::Dist::SOLOEXEC} --minimal-ohai" }

  when_the_repository "creates nodes" do
    let(:nodes_dir) { File.join(@repository_dir, "nodes") }
    let(:node_file) { Dir[File.join(nodes_dir, "*.json")][0] }

    before do
      file "config/solo.rb", <<~EOM
        chef_repo_path "#{@repository_dir}"
      EOM
      result = shell_out("bundle exec chef-solo -c \"#{path_to("config/solo.rb")}\" -l debug", cwd: chef_dir)
      result.error!
    end

    describe "on unix", :unix_only do
      describe "the nodes directory" do
        it "has the correct permissions" do
          expect(File.stat(nodes_dir).mode.to_s(8)[-3..-1]).to eq("700")
        end
      end

      describe "the node file" do
        it "has the correct permissions" do
          expect(File.stat(node_file).mode.to_s(8)[-4..-1]).to eq("0600")
        end
      end
    end

    describe "on windows", :windows_only do
      let(:read_mask) { Chef::ReservedNames::Win32::API::Security::GENERIC_READ }
      let(:write_mask) { Chef::ReservedNames::Win32::API::Security::GENERIC_WRITE }
      let(:execute_mask) { Chef::ReservedNames::Win32::API::Security::GENERIC_EXECUTE }

      describe "the nodes directory" do
        it "has the correct permissions" do
          expect(Chef::ReservedNames::Win32::File.file_access_check(nodes_dir, read_mask)).to be(true)
          expect(Chef::ReservedNames::Win32::File.file_access_check(nodes_dir, write_mask)).to be(true)
          expect(Chef::ReservedNames::Win32::File.file_access_check(nodes_dir, execute_mask)).to be(true)
        end
      end

      describe "the node file" do
        it "has the correct permissions" do
          expect(Chef::ReservedNames::Win32::File.file_access_check(node_file, read_mask)).to be(true)
          expect(Chef::ReservedNames::Win32::File.file_access_check(node_file, write_mask)).to be(true)
          expect(Chef::ReservedNames::Win32::File.file_access_check(node_file, execute_mask)).to be(false)
        end
      end
    end
  end

  when_the_repository "has a cookbook with a basic recipe" do
    before do
      file "cookbooks/x/metadata.rb", cookbook_x_100_metadata_rb
      file "cookbooks/x/recipes/default.rb", 'puts "ITWORKS"'
    end

    it "should complete with success" do
      file "config/solo.rb", <<~EOM
        cookbook_path "#{path_to("cookbooks")}"
        file_cache_path "#{path_to("config/cache")}"
      EOM
      result = shell_out("#{chef_solo} -c \"#{path_to("config/solo.rb")}\" -o 'x::default' -l debug", cwd: chef_dir)
      result.error!
      expect(result.stdout).to include("ITWORKS")
    end

    it "should evaluate its node.json file" do
      file "config/solo.rb", <<~EOM
        cookbook_path "#{path_to("cookbooks")}"
        file_cache_path "#{path_to("config/cache")}"
      EOM

      file "config/node.json", <<~E
        {"run_list":["x::default"]}
      E

      result = shell_out("#{chef_solo} -c \"#{path_to("config/solo.rb")}\" -j '#{path_to("config/node.json")}' -l debug", cwd: chef_dir)
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
      file "config/solo.rb", <<~EOM
        cookbook_path "#{path_to("cookbooks")}"
        file_cache_path "#{path_to("config/cache")}"
      EOM
      result = shell_out("#{chef_solo} -c \"#{path_to("config/solo.rb")}\" -o 'x::default' -l debug", cwd: chef_dir)
      expect(result.exitstatus).to eq(1)
      expect(result.stdout).to include("WARN: MissingCookbookDependency")
    end
  end

  when_the_repository "has a cookbook with an incompatible chef_version" do
    before do
      file "cookbooks/x/metadata.rb", cb_metadata("x", "1.0.0", "\nchef_version '~> 999.0'")
      file "cookbooks/x/recipes/default.rb", 'puts "ITWORKS"'
      file "config/solo.rb", <<~EOM
        cookbook_path "#{path_to("cookbooks")}"
        file_cache_path "#{path_to("config/cache")}"
      EOM
    end

    it "should exit with an error" do
      result = shell_out("#{chef_solo} -c \"#{path_to("config/solo.rb")}\" -o 'x::default' -l debug", cwd: chef_dir)
      expect(result.exitstatus).to eq(1)
      expect(result.stdout).to include("Chef::Exceptions::CookbookChefVersionMismatch")
    end
  end

  when_the_repository "has a cookbook with an incompatible ohai_version" do
    before do
      file "cookbooks/x/metadata.rb", cb_metadata("x", "1.0.0", "\nohai_version '~> 999.0'")
      file "cookbooks/x/recipes/default.rb", 'puts "ITWORKS"'
      file "config/solo.rb", <<~EOM
        cookbook_path "#{path_to("cookbooks")}"
        file_cache_path "#{path_to("config/cache")}"
      EOM
    end

    it "should exit with an error" do
      result = shell_out("#{chef_solo} -c \"#{path_to("config/solo.rb")}\" -o 'x::default' -l debug", cwd: chef_dir)
      expect(result.exitstatus).to eq(1)
      expect(result.stdout).to include("Chef::Exceptions::CookbookOhaiVersionMismatch")
    end
  end

  when_the_repository "has a cookbook with a recipe with sleep" do
    before do
      directory "logs"
      file "logs/runs.log", ""
      file "cookbooks/x/metadata.rb", cookbook_x_100_metadata_rb
      file "cookbooks/x/recipes/default.rb", <<~EOM
        ruby_block "sleeping" do
          block do
            retries = 200
            while IO.read(Chef::Config[:log_location]) !~ /.* is running, will wait for it to finish and then run./
              sleep 0.1
              raise "we ran out of retries" if ( retries -= 1 ) <= 0
            end
          end
        end
      EOM
    end

    it "while running solo concurrently" do
      file "config/solo.rb", <<~EOM
        cookbook_path "#{path_to("cookbooks")}"
        file_cache_path "#{path_to("config/cache")}"
      EOM
      # We have a timeout protection here so that if due to some bug
      # run_lock gets stuck we can discover it.
      expect do
        Timeout.timeout(120) do
          chef_dir = File.join(File.dirname(__FILE__), "..", "..", "..")

          threads = []

          # Instantiate the first chef-solo run
          threads << Thread.new do
            s1 = Process.spawn("#{chef_solo} -c \"#{path_to("config/solo.rb")}\" -o 'x::default'  -l debug -L #{path_to("logs/runs.log")}", chdir: chef_dir)
            Process.waitpid(s1)
          end

          # Instantiate the second chef-solo run
          threads << Thread.new do
            s2 = Process.spawn("#{chef_solo} -c \"#{path_to("config/solo.rb")}\" -o 'x::default'  -l debug -L #{path_to("logs/runs.log")}", chdir: chef_dir)
            Process.waitpid(s2)
          end

          threads.each(&:join)
        end
      end.not_to raise_error

      # Unfortunately file / directory helpers in integration tests
      # are implemented using before(:each) so we need to do all below
      # checks in one example.
      run_log = File.read(path_to("logs/runs.log"))

      # second run should have a message which indicates it's waiting for the first run
      expect(run_log).to match(/.* is running, will wait for it to finish and then run./)

      # both of the runs should succeed
      expect(run_log.lines.reject { |l| !l.include? "Run complete in" }.length).to eq(2)
    end

  end
end
