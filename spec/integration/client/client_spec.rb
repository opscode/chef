require "support/shared/integration/integration_helper"
require "chef/mixin/shell_out"
require "tiny_server"
require "tmpdir"
require "chef/dist"

describe "chef-client" do

  def recipes_filename
    File.join(CHEF_SPEC_DATA, "recipes.tgz")
  end

  def start_tiny_server(server_opts = {})
    @server = TinyServer::Manager.new(server_opts)
    @server.start
    @api = TinyServer::API.instance
    @api.clear
    #
    # trivial endpoints
    #
    # just a normal file
    # (expected_content should be uncompressed)
    @api.get("/recipes.tgz", 200) do
      File.open(recipes_filename, "rb", &:read)
    end
  end

  def stop_tiny_server
    @server.stop
    @server = @api = nil
  end

  include IntegrationSupport
  include Chef::Mixin::ShellOut

  let(:chef_dir) { File.join(File.dirname(__FILE__), "..", "..", "..", "bin") }

  # Invoke `chef-client` as `ruby PATH/TO/chef-client`. This ensures the
  # following constraints are satisfied:
  # * Windows: windows can only run batch scripts as bare executables. Rubygems
  # creates batch wrappers for installed gems, but we don't have batch wrappers
  # in the source tree.
  # * Other `chef-client` in PATH: A common case is running the tests on a
  # machine that has omnibus chef installed. In that case we need to ensure
  # we're running `chef-client` from the source tree and not the external one.
  # cf. CHEF-4914
  let(:chef_client) { "bundle exec #{Chef::Dist::CLIENT} --minimal-ohai" }
  let(:chef_solo) { "bundle exec #{Chef::Dist::SOLOEXEC} --minimal-ohai" }

  when_the_repository "has a cookbook with a no-op recipe" do
    before { file "cookbooks/x/recipes/default.rb", "" }

    it "should complete with success" do
      file "config/client.rb", <<~EOM
        local_mode true
        cookbook_path "#{path_to("cookbooks")}"
      EOM

      shell_out!("#{chef_client} -c \"#{path_to("config/client.rb")}\" -o 'x::default'", cwd: chef_dir)
    end

    it "should complete successfully with --no-listen" do
      file "config/client.rb", <<~EOM
        local_mode true
        cookbook_path "#{path_to("cookbooks")}"
      EOM

      result = shell_out("#{chef_client} --no-listen -c \"#{path_to("config/client.rb")}\" -o 'x::default'", cwd: chef_dir)
      result.error!
    end

    it "should be able to node.save with bad utf8 characters in the node data" do
      file "cookbooks/x/attributes/default.rb", 'default["badutf8"] = "Elan Ruusam\xE4e"'
      result = shell_out("#{chef_client} -z -r 'x::default' --disable-config", cwd: path_to(""))
      result.error!
    end

    context "and no config file" do
      it "should complete with success when cwd is just above cookbooks and paths are not specified" do
        result = shell_out("#{chef_client} -z -o 'x::default' --disable-config", cwd: path_to(""))
        result.error!
      end

      it "should complete with success when cwd is below cookbooks and paths are not specified" do
        result = shell_out("#{chef_client} -z -o 'x::default' --disable-config", cwd: path_to("cookbooks/x"))
        result.error!
      end

      it "should fail when cwd is below high above and paths are not specified" do
        result = shell_out("#{chef_client} -z -o 'x::default' --disable-config", cwd: File.expand_path("..", path_to("")))
        expect(result.exitstatus).to eq(1)
      end
    end

    context "and a config file under .chef/knife.rb" do
      before { file ".chef/knife.rb", "xxx.xxx" }

      it "should load .chef/knife.rb when -z is specified" do
        result = shell_out("#{chef_client} -z -o 'x::default'", cwd: path_to(""))
        # FATAL: Configuration error NoMethodError: undefined method `xxx' for nil:NilClass
        expect(result.stdout).to include("xxx")
      end

    end

    it "should complete with success" do
      file "config/client.rb", <<~EOM
        local_mode true
        cookbook_path "#{path_to("cookbooks")}"
      EOM

      result = shell_out("#{chef_client} -c \"#{path_to("config/client.rb")}\" -o 'x::default'", cwd: chef_dir)
      result.error!
    end

    context "and a private key" do
      before do
        file "mykey.pem", <<~EOM
          -----BEGIN RSA PRIVATE KEY-----
          MIIEogIBAAKCAQEApubutqtYYQ5UiA9QhWP7UvSmsfHsAoPKEVVPdVW/e8Svwpyf
          0Xef6OFWVmBE+W442ZjLOe2y6p2nSnaq4y7dg99NFz6X+16mcKiCbj0RCiGqCvCk
          NftHhTgO9/RFvCbmKZ1RKNob1YzLrFpxBHaSh9po+DGWhApcd+I+op+ZzvDgXhNn
          0nauZu3rZmApI/r7EEAOjFedAXs7VPNXhhtZAiLSAVIrwU3ZajtSzgXOxbNzgj5O
          AAAMmThK+71qPdffAdO4J198H6/MY04qgtFo7vumzCq0UCaGZfmeI1UNE4+xQWwP
          HJ3pDAP61C6Ebx2snI2kAd9QMx9Y78nIedRHPwIDAQABAoIBAHssRtPM1GacWsom
          8zfeN6ZbI4KDlbetZz0vhnqDk9NVrpijWlcOP5dwZXVNitnB/HaqCqFvyPDY9JNB
          zI/pEFW4QH59FVDP42mVEt0keCTP/1wfiDDGh1vLqVBYl/ZphscDcNgDTzNkuxMx
          k+LFVxKnn3w7rGc59lALSkpeGvbbIDjp3LUMlUeCF8CIFyYZh9ZvXe4OCxYdyjxb
          i8tnMLKvJ4Psbh5jMapsu3rHQkfPdqzztQUz8vs0NYwP5vWge46FUyk+WNm/IhbJ
          G3YM22nwUS8Eu2bmTtADSJolATbCSkOwQ1D+Fybz/4obfYeGaCdOqB05ttubhenV
          ShsAb7ECgYEA20ecRVxw2S7qA7sqJ4NuYOg9TpfGooptYNA1IP971eB6SaGAelEL
          awYkGNuu2URmm5ElZpwJFFTDLGA7t2zB2xI1FeySPPIVPvJGSiZoFQOVlIg9WQzK
          7jTtFQ/tOMrF+bigEUJh5bP1/7HzqSpuOsPjEUb2aoCTp+tpiRGL7TUCgYEAwtns
          g3ysrSEcTzpSv7fQRJRk1lkBhatgNd0oc+ikzf74DaVLhBg1jvSThDhiDCdB59mr
          Jh41cnR1XqE8jmdQbCDRiFrI1Pq6TPaDZFcovDVE1gue9x86v3FOH2ukPG4d2/Xy
          HevXjThtpMMsWFi0JYXuzXuV5HOvLZiP8sN3lSMCgYANpdxdGM7RRbE9ADY0dWK2
          V14ReTLcxP7fyrWz0xLzEeCqmomzkz3BsIUoouu0DCTSw+rvAwExqcDoDylIVlWO
          fAifz7SeZHbcDxo+3TsXK7zwnLYsx7YNs2+aIv6hzUUbMNmNmXMcZ+IEwx+mRMTN
          lYmZdrA5mr0V83oDFPt/jQKBgC74RVE03pMlZiObFZNtheDiPKSG9Bz6wMh7NWMr
          c37MtZLkg52mEFMTlfPLe6ceV37CM8WOhqe+dwSGrYhOU06dYqUR7VOZ1Qr0aZvo
          fsNPu/Y0+u7rMkgv0fs1AXQnvz7kvKaF0YITVirfeXMafuKEtJoH7owRbur42cpV
          YCAtAoGAP1rHOc+w0RUcBK3sY7aErrih0OPh9U5bvJsrw1C0FIZhCEoDVA+fNIQL
          syHLXYFNy0OxMtH/bBAXBGNHd9gf5uOnqh0pYcbe/uRAxumC7Rl0cL509eURiA2T
          +vFmf54y9YdnLXaqv+FhJT6B6V7WX7IpU9BMqJY1cJYXHuHG2KA=
          -----END RSA PRIVATE KEY-----
        EOM
      end

      it "should complete with success even with a client key" do
        file "config/client.rb", <<~EOM
          local_mode true
          client_key #{path_to("mykey.pem").inspect}
          cookbook_path #{path_to("cookbooks").inspect}
        EOM

        result = shell_out("#{chef_client} -c \"#{path_to("config/client.rb")}\" -o 'x::default'", cwd: chef_dir)
        result.error!
      end

      it "should run recipes specified directly on the command line" do
        file "config/client.rb", <<~EOM
          local_mode true
          client_key #{path_to("mykey.pem").inspect}
          cookbook_path #{path_to("cookbooks").inspect}
        EOM

        file "arbitrary.rb", <<~EOM
          file #{path_to("tempfile.txt").inspect} do
            content '1'
          end
        EOM

        file "arbitrary2.rb", <<~EOM
          file #{path_to("tempfile2.txt").inspect} do
            content '2'
          end
        EOM

        result = shell_out("#{chef_client} -c \"#{path_to("config/client.rb")}\" #{path_to("arbitrary.rb")} #{path_to("arbitrary2.rb")}", cwd: chef_dir)
        result.error!

        expect(IO.read(path_to("tempfile.txt"))).to eq("1")
        expect(IO.read(path_to("tempfile2.txt"))).to eq("2")
      end

      it "should run recipes specified as relative paths directly on the command line" do
        file "config/client.rb", <<~EOM
          local_mode true
          client_key #{path_to("mykey.pem").inspect}
          cookbook_path #{path_to("cookbooks").inspect}
        EOM

        file "arbitrary.rb", <<~EOM
          file #{path_to("tempfile.txt").inspect} do
            content '1'
          end
        EOM

        result = shell_out("#{chef_client} -c \"#{path_to("config/client.rb")}\" arbitrary.rb", cwd: path_to(""))
        result.error!

        expect(IO.read(path_to("tempfile.txt"))).to eq("1")
      end

      it "should run recipes specified directly on the command line AFTER recipes in the run list" do
        file "config/client.rb", <<~EOM
          local_mode true
          client_key #{path_to("mykey.pem").inspect}
          cookbook_path #{path_to("cookbooks").inspect}
        EOM

        file "cookbooks/x/recipes/constant_definition.rb", <<~EOM
          class ::Blah
            THECONSTANT = '1'
          end
        EOM

        file "arbitrary.rb", <<~EOM
          file #{path_to("tempfile.txt").inspect} do
            content ::Blah::THECONSTANT
          end
        EOM

        result = shell_out("#{chef_client} -c \"#{path_to("config/client.rb")}\" -o x::constant_definition arbitrary.rb", cwd: path_to(""))
        result.error!

        expect(IO.read(path_to("tempfile.txt"))).to eq("1")
      end

      it "should run recipes specified directly on the command line AFTER recipes in the run list (without an override_runlist this time)" do
        file "config/client.rb", <<~EOM
          local_mode true
          client_key #{path_to("mykey.pem").inspect}
          cookbook_path #{path_to("cookbooks").inspect}
        EOM

        file "config/dna.json", <<~EOM
          {
            "run_list": [ "recipe[x::constant_definition]" ]
          }
        EOM

        file "cookbooks/x/recipes/constant_definition.rb", <<~EOM
          class ::Blah
            THECONSTANT = '1'
          end
        EOM

        file "arbitrary.rb", <<~EOM
          file #{path_to("tempfile.txt").inspect} do
            content ::Blah::THECONSTANT
          end
        EOM

        result = shell_out("#{chef_client} -c \"#{path_to("config/client.rb")}\" -j \"#{path_to("config/dna.json")}\" arbitrary.rb", cwd: path_to(""))
        result.error!

        expect(IO.read(path_to("tempfile.txt"))).to eq("1")
      end

      it "an override_runlist of an empty string should allow a recipe specified directly on the command line to be the only one run" do
        file "config/client.rb", <<~EOM
          local_mode true
          client_key #{path_to("mykey.pem").inspect}
          cookbook_path #{path_to("cookbooks").inspect}
          class ::Blah
            THECONSTANT = "1"
          end
        EOM

        file "config/dna.json", <<~EOM
          {
            "run_list": [ "recipe[x::constant_definition]" ]
          }
        EOM

        file "cookbooks/x/recipes/constant_definition.rb", <<~EOM
          class ::Blah
            THECONSTANT = "2"
          end
        EOM

        file "arbitrary.rb", <<~EOM
          raise "this test failed" unless ::Blah::THECONSTANT == "1"
          file #{path_to("tempfile.txt").inspect} do
            content ::Blah::THECONSTANT
          end
        EOM

        result = shell_out("#{chef_client} -c \"#{path_to("config/client.rb")}\" -j \"#{path_to("config/dna.json")}\" -o \"\" arbitrary.rb", cwd: path_to(""))
        result.error!

        expect(IO.read(path_to("tempfile.txt"))).to eq("1")
      end

    end

    it "should complete with success when passed the -z flag" do
      file "config/client.rb", <<~EOM
        chef_server_url 'http://omg.com/blah'
        cookbook_path "#{path_to("cookbooks")}"
      EOM

      result = shell_out("#{chef_client} -c \"#{path_to("config/client.rb")}\" -o 'x::default' -z", cwd: chef_dir)
      result.error!
    end

    it "should complete with success when passed the --local-mode flag" do
      file "config/client.rb", <<~EOM
        chef_server_url 'http://omg.com/blah'
        cookbook_path "#{path_to("cookbooks")}"
      EOM

      result = shell_out("#{chef_client} -c \"#{path_to("config/client.rb")}\" -o 'x::default' --local-mode", cwd: chef_dir)
      result.error!
    end

    it "should not print SSL warnings when running in local-mode" do
      file "config/client.rb", <<~EOM
        chef_server_url 'http://omg.com/blah'
        cookbook_path "#{path_to("cookbooks")}"
      EOM

      result = shell_out("#{chef_client} -c \"#{path_to("config/client.rb")}\" -o 'x::default' --local-mode", cwd: chef_dir)
      expect(result.stdout).not_to include("SSL validation of HTTPS requests is disabled.")
      result.error!
    end

    it "should complete with success when passed -z and --chef-zero-port" do
      file "config/client.rb", <<~EOM
        chef_server_url 'http://omg.com/blah'
        cookbook_path "#{path_to("cookbooks")}"
      EOM

      result = shell_out("#{chef_client} -c \"#{path_to("config/client.rb")}\" -o 'x::default' -z", cwd: chef_dir)
      result.error!
    end

    it "should complete with success when setting the run list with -r" do
      file "config/client.rb", <<~EOM
        chef_server_url 'http://omg.com/blah'
        cookbook_path "#{path_to("cookbooks")}"
      EOM

      result = shell_out("#{chef_client} -c \"#{path_to("config/client.rb")}\" -r 'x::default' -z -l info", cwd: chef_dir)
      expect(result.stdout).not_to include("Overridden Run List")
      expect(result.stdout).to include("Run List is [recipe[x::default]]")
      result.error!
    end

    it "should complete with success when using --profile-ruby and output a profile file", :not_supported_on_aix do
      file "config/client.rb", <<~EOM
        local_mode true
        cookbook_path "#{path_to("cookbooks")}"
      EOM
      result = shell_out!("#{chef_client} -c \"#{path_to("config/client.rb")}\" -o 'x::default' -z --profile-ruby", cwd: chef_dir)
      result.error!
      expect(File.exist?(path_to("config/local-mode-cache/cache/graph_profile.out"))).to be true
    end

    it "doesn't produce a profile when --profile-ruby is not present" do
      file "config/client.rb", <<~EOM
        local_mode true
        cookbook_path "#{path_to("cookbooks")}"
      EOM
      result = shell_out!("#{chef_client} -c \"#{path_to("config/client.rb")}\" -o 'x::default' -z", cwd: chef_dir)
      result.error!
      expect(File.exist?(path_to("config/local-mode-cache/cache/graph_profile.out"))).to be false
    end
  end

  when_the_repository "has a cookbook that outputs some node attributes" do
    before do
      file "cookbooks/x/recipes/default.rb", <<~'EOM'
        puts "COOKBOOKS: #{node[:cookbooks]}"
      EOM
      file "cookbooks/x/metadata.rb", <<~EOM
        name 'x'
        version '0.0.1'
      EOM
      file "config/client.rb", <<~EOM
        local_mode true
        cookbook_path "#{path_to("cookbooks")}"
      EOM
    end

    it "should have a cookbook attribute" do
      result = shell_out("#{chef_client} -c \"#{path_to("config/client.rb")}\" -o 'x::default' --no-fork", cwd: chef_dir)
      result.error!
      expect(result.stdout).to include('COOKBOOKS: {"x"=>{"version"=>"0.0.1"}}')
    end
  end

  when_the_repository "has a cookbook that should fail chef_version checks" do
    before do
      file "cookbooks/x/recipes/default.rb", ""
      file "cookbooks/x/metadata.rb", <<~EOM
        name 'x'
        version '0.0.1'
        chef_version '~> 999.99'
      EOM
      file "config/client.rb", <<~EOM
        local_mode true
        cookbook_path "#{path_to("cookbooks")}"
      EOM
    end
    it "should fail the chef client run" do
      command = shell_out("#{chef_client} -c \"#{path_to("config/client.rb")}\" -o 'x::default' --no-fork", cwd: chef_dir)
      expect(command.exitstatus).to eql(1)
      expect(command.stdout).to match(/Chef::Exceptions::CookbookChefVersionMismatch/)
    end
  end

  when_the_repository "has a cookbook that uses cheffish resources" do
    before do
      file "cookbooks/x/recipes/default.rb", <<-EOM
        raise "Cheffish was loaded before we used any cheffish things!" if defined?(Cheffish::VERSION)
        ran_block = false
        got_server = with_chef_server 'https://blah.com' do
          ran_block = true
          run_context.cheffish.current_chef_server
        end
        raise "with_chef_server block was not run!" if !ran_block
        raise "Cheffish was not loaded when we did cheffish things!" if !defined?(Cheffish::VERSION)
        raise "current_chef_server did not return its value!" if got_server[:chef_server_url] != 'https://blah.com'
      EOM
      file "config/client.rb", <<-EOM
        local_mode true
        cookbook_path "#{path_to("cookbooks")}"
      EOM
    end

    it "the cheffish DSL is loaded lazily" do
      command = shell_out("#{chef_client} -c \"#{path_to("config/client.rb")}\" -o 'x::default' --no-fork", cwd: chef_dir)
      expect(command.exitstatus).to eql(0)
    end
  end

  when_the_repository "has a cookbook that generates deprecation warnings" do
    before do
      file "cookbooks/x/recipes/default.rb", <<-EOM
        Chef.deprecated(:internal_api, "Test deprecation")
        Chef.deprecated(:internal_api, "Test deprecation")
      EOM
    end

    def match_indices(regex, str)
      result = []
      pos = 0
      while match = regex.match(str, pos)
        result << match.begin(0)
        pos = match.end(0) + 1
      end
      result
    end

    it "should output each deprecation warning only once, at the end of the run" do
      file "config/client.rb", <<~EOM
        local_mode true
        cookbook_path "#{path_to("cookbooks")}"
        # Mimick what happens when you are on the console
        formatters << :doc
        log_level :warn
      EOM

      ENV.delete("CHEF_TREAT_DEPRECATION_WARNINGS_AS_ERRORS")

      result = shell_out!("#{chef_client} -c \"#{path_to("config/client.rb")}\" -o 'x::default'", cwd: chef_dir)
      expect(result.error?).to be_falsey

      # Search to the end of the client run in the output
      run_complete = result.stdout.index("Running handlers complete")
      expect(run_complete).to be >= 0

      # Make sure there is exactly one result for each, and that it occurs *after* the complete message.
      expect(match_indices(/Test deprecation/, result.stdout)).to match([ be > run_complete ])
    end
  end

  when_the_repository "has a cookbook that deploys a file" do
    before do
      file "cookbooks/x/recipes/default.rb", <<~RECIPE
        cookbook_file #{path_to("tempfile.txt").inspect} do
          source "my_file"
        end
      RECIPE

      file "cookbooks/x/files/my_file", <<~FILE
        this is my file
      FILE
    end

    [true, false].each do |lazy|
      context "with no_lazy_load set to #{lazy}" do
        it "should create the file" do
          file "config/client.rb", <<~EOM
            no_lazy_load #{lazy}
            local_mode true
            cookbook_path "#{path_to("cookbooks")}"
          EOM
          result = shell_out("#{chef_client} -l debug -c \"#{path_to("config/client.rb")}\" -o 'x::default' --no-fork", cwd: chef_dir)
          result.error!

          expect(IO.read(path_to("tempfile.txt")).strip).to eq("this is my file")
        end
      end
    end
  end

  when_the_repository "has a cookbook with an ohai plugin" do
    before do
      file "cookbooks/x/recipes/default.rb", <<~RECIPE
        file #{path_to("tempfile.txt").inspect} do
          content node["english"]["version"]
        end
      RECIPE

      file "cookbooks/x/ohai/english.rb", <<-OHAI
        Ohai.plugin(:English) do
          provides 'english'

          collect_data do
            english Mash.new
            english[:version] = "2014"
          end
        end
      OHAI

      file "config/client.rb", <<~EOM
        local_mode true
        cookbook_path "#{path_to("cookbooks")}"
      EOM
    end

    it "should run the ohai plugin" do
      result = shell_out("#{chef_client} -l debug -c \"#{path_to("config/client.rb")}\" -o 'x::default' --no-fork", cwd: chef_dir)
      result.error!

      expect(IO.read(path_to("tempfile.txt"))).to eq("2014")
    end
  end

  # Fails on appveyor, but works locally on windows and on windows hosts in Ci.
  context "when using recipe-url", :skip_appveyor do
    before(:each) do
      start_tiny_server
    end

    after(:each) do
      stop_tiny_server
    end

    let(:tmp_dir) { Dir.mktmpdir("recipe-url") }

    it "should complete with success when passed -z and --recipe-url" do
      file "config/client.rb", <<~EOM
        chef_repo_path "#{tmp_dir}"
      EOM
      result = shell_out("#{chef_client} -c \"#{path_to("config/client.rb")}\" --recipe-url=http://localhost:9000/recipes.tgz -o 'x::default' -z", cwd: tmp_dir)
      result.error!
    end

    it "should fail when passed --recipe-url and not passed -z" do
      result = shell_out("#{chef_client} --recipe-url=http://localhost:9000/recipes.tgz", cwd: tmp_dir)
      expect(result.exitstatus).not_to eq(0)
    end

    it "should fail when passed --recipe-url with a file that doesn't exist" do
      broken_path = File.join(CHEF_SPEC_DATA, "recipes_dont_exist.tgz")
      result = shell_out("#{chef_client} --recipe-url=#{broken_path}", cwd: tmp_dir)
      expect(result.exitstatus).not_to eq(0)
    end
  end

  when_the_repository "has a cookbook with broken metadata.rb, but has metadata.json" do
    before do
      file "cookbooks/x/recipes/default.rb", ""
      file "cookbooks/x/metadata.rb", <<~EOM
        name 'x'
        version '0.0.1'
        raise "TEH SADNESS"
      EOM
      file "cookbooks/x/metadata.json", <<~EOM
        {
          "name": "x",
          "version": "0.0.1"
        }
      EOM

      file "config/client.rb", <<~EOM
        local_mode true
        cookbook_path "#{path_to("cookbooks")}"
      EOM
    end

    it "the chef client run should succeed" do
      command = shell_out("#{chef_client} -c \"#{path_to("config/client.rb")}\" -o 'x::default' --no-fork", cwd: chef_dir)
      command.error!
    end

    it "a chef-solo run should succeed" do
      command = shell_out("#{chef_solo} -c \"#{path_to("config/client.rb")}\" -o 'x::default' --no-fork", cwd: chef_dir)
      command.error!
    end
  end

  when_the_repository "has a cookbook that logs at the info level" do
    before do
      file "cookbooks/x/recipes/default.rb", <<EOM
      log "info level" do
        level :info
      end
EOM
      file "config/client.rb", <<~EOM
        local_mode true
        cookbook_path "#{path_to("cookbooks")}"
      EOM
    end

    it "a chef client run should not log to info by default" do
      command = shell_out("#{chef_client} -c \"#{path_to("config/client.rb")}\" -o 'x::default' --no-fork", cwd: chef_dir)
      command.error!
      expect(command.stdout).not_to include("INFO")
    end

    it "a chef client run to a pipe should not log to info by default" do
      command = shell_out("#{chef_client} -c \"#{path_to("config/client.rb")}\" -o 'x::default' --no-fork | tee #{path_to("chefrun.out")}", cwd: chef_dir)
      command.error!
      expect(command.stdout).not_to include("INFO")
    end

    it "a chef solo run should not log to info by default" do
      command = shell_out("#{chef_solo} -c \"#{path_to("config/client.rb")}\" -o 'x::default' --no-fork", cwd: chef_dir)
      command.error!
      expect(command.stdout).not_to include("INFO")
    end

    it "a chef solo run to a pipe should not log to info by default" do
      command = shell_out("#{chef_solo} -c \"#{path_to("config/client.rb")}\" -o 'x::default' --no-fork | tee #{path_to("chefrun.out")}", cwd: chef_dir)
      command.error!
      expect(command.stdout).not_to include("INFO")
    end
  end

  when_the_repository "has a cookbook that knows if we're running forked" do
    before do
      file "cookbooks/x/recipes/default.rb", <<~EOM
        puts Chef::Config[:client_fork] ? "WITHFORK" : "NOFORK"
      EOM
      file "config/client.rb", <<~EOM
        local_mode true
        cookbook_path "#{path_to("cookbooks")}"
      EOM
    end

    it "chef-client runs by default with no supervisor" do
      command = shell_out("#{chef_client} -c \"#{path_to("config/client.rb")}\" -o 'x::default'", cwd: chef_dir)
      command.error!
      expect(command.stdout).to include("NOFORK")
    end

    it "chef-solo runs by default with no supervisor" do
      command = shell_out("#{chef_solo} -c \"#{path_to("config/client.rb")}\" -o 'x::default'", cwd: chef_dir)
      command.error!
      expect(command.stdout).to include("NOFORK")
    end

    it "chef-client --no-fork does not fork" do
      command = shell_out("#{chef_client} -c \"#{path_to("config/client.rb")}\" -o 'x::default' --no-fork", cwd: chef_dir)
      command.error!
      expect(command.stdout).to include("NOFORK")
    end

    it "chef-solo --no-fork does not fork" do
      command = shell_out("#{chef_solo} -c \"#{path_to("config/client.rb")}\" -o 'x::default' --no-fork", cwd: chef_dir)
      command.error!
      expect(command.stdout).to include("NOFORK")
    end

    it "chef-client with --fork uses a supervisor" do
      command = shell_out("#{chef_client} -c \"#{path_to("config/client.rb")}\" -o 'x::default' --fork", cwd: chef_dir)
      command.error!
      expect(command.stdout).to include("WITHFORK")
    end

    it "chef-solo with --fork uses a supervisor" do
      command = shell_out("#{chef_solo} -c \"#{path_to("config/client.rb")}\" -o 'x::default' --fork", cwd: chef_dir)
      command.error!
      expect(command.stdout).to include("WITHFORK")
    end
  end

  when_the_repository "has a cookbook that knows if we're running forked, and configures forking in config.rb" do
    before do
      file "cookbooks/x/recipes/default.rb", <<~EOM
        puts Chef::Config[:client_fork] ? "WITHFORK" : "NOFORK"
      EOM
      file "config/client.rb", <<~EOM
        local_mode true
        cookbook_path "#{path_to("cookbooks")}"
        client_fork true
      EOM
    end

    it "chef-client uses a supervisor" do
      command = shell_out("#{chef_client} -c \"#{path_to("config/client.rb")}\" -o 'x::default'", cwd: chef_dir)
      command.error!
      expect(command.stdout).to include("WITHFORK")
    end

    it "chef-solo uses a supervisor" do
      command = shell_out("#{chef_solo} -c \"#{path_to("config/client.rb")}\" -o 'x::default'", cwd: chef_dir)
      command.error!
      expect(command.stdout).to include("WITHFORK")
    end
  end

  when_the_repository "has a cookbook that knows if we're running forked, and configures no-forking in config.rb" do
    before do
      file "cookbooks/x/recipes/default.rb", <<~EOM
        puts Chef::Config[:client_fork] ? "WITHFORK" : "NOFORK"
      EOM
      file "config/client.rb", <<~EOM
        local_mode true
        cookbook_path "#{path_to("cookbooks")}"
        client_fork false
      EOM
    end

    it "chef-client uses a supervisor" do
      command = shell_out("#{chef_client} -c \"#{path_to("config/client.rb")}\" -o 'x::default'", cwd: chef_dir)
      command.error!
      expect(command.stdout).to include("NOFORK")
    end

    it "chef-solo uses a supervisor" do
      command = shell_out("#{chef_solo} -c \"#{path_to("config/client.rb")}\" -o 'x::default'", cwd: chef_dir)
      command.error!
      expect(command.stdout).to include("NOFORK")
    end
  end
end
