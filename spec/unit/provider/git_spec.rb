#
# Author:: Daniel DeLeo (<dan@kallistec.com>)
# Copyright:: Copyright 2008-2016, Chef Software Inc.
# License:: Apache License, Version 2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

require "spec_helper"
describe Chef::Provider::Git do

  let(:parent_dir) { "/my/deploy" }
  let(:repo_dir) { ::File.join parent_dir, "dir" }
  let(:repo_git_dir) { ::File.join repo_dir, ".git" }

  before(:each) do
    allow(STDOUT).to receive(:tty?).and_return(true)
    @original_log_level = Chef::Log.level
    Chef::Log.level = :info

    @current_resource = Chef::Resource::Git.new("web2.0 app")
    @current_resource.revision("d35af14d41ae22b19da05d7d03a0bafc321b244c")

    @resource = Chef::Resource::Git.new("web2.0 app")
    @resource.repository "git://github.com/opscode/chef.git"
    @resource.destination repo_dir
    @resource.revision "d35af14d41ae22b19da05d7d03a0bafc321b244c"
    @node = Chef::Node.new
    @events = Chef::EventDispatch::Dispatcher.new
    @run_context = Chef::RunContext.new(@node, {}, @events)
    @provider = Chef::Provider::Git.new(@resource, @run_context)
    @provider.current_resource = @current_resource
  end

  after(:each) do
    Chef::Log.level = @original_log_level
  end

  context "determining the revision of the currently deployed checkout" do

    before do
      @stdout = double("standard out")
      @stderr = double("standard error")
      @exitstatus = double("exitstatus")
    end

    it "sets the current revision to nil if the deploy dir does not exist" do
      expect(::File).to receive(:exist?).with(repo_git_dir).and_return(false)
      expect(@provider.find_current_revision).to be_nil
    end

    it "determines the current revision when there is one" do
      expect(::File).to receive(:exist?).with(repo_git_dir).and_return(true)
      @stdout = "9b4d8dc38dd471246e7cfb1c3c1ad14b0f2bee13\n"
      expect(@provider).to receive(:shell_out!).with("git rev-parse HEAD", { :cwd => repo_dir, :returns => [0, 128], :log_tag => "git[web2.0 app]" }).and_return(double("ShellOut result", :stdout => @stdout))
      expect(@provider.find_current_revision).to eql("9b4d8dc38dd471246e7cfb1c3c1ad14b0f2bee13")
    end

    it "gives the current revision as nil when there is no current revision" do
      expect(::File).to receive(:exist?).with(repo_git_dir).and_return(true)
      @stderr = "fatal: Not a git repository (or any of the parent directories): .git"
      @stdout = ""
      expect(@provider).to receive(:shell_out!).with("git rev-parse HEAD", :cwd => repo_dir, :returns => [0, 128], :log_tag => "git[web2.0 app]" ).and_return(double("ShellOut result", :stdout => "", :stderr => @stderr))
      expect(@provider.find_current_revision).to be_nil
    end
  end

  it "creates a current_resource with the currently deployed revision when a clone exists in the destination dir" do
    allow(@provider).to receive(:find_current_revision).and_return("681c9802d1c62a45b490786c18f0b8216b309440")
    @provider.load_current_resource
    expect(@provider.current_resource.name).to eql(@resource.name)
    expect(@provider.current_resource.revision).to eql("681c9802d1c62a45b490786c18f0b8216b309440")
  end

  it "keeps the node and resource passed to it on initialize" do
    expect(@provider.node).to equal(@node)
    expect(@provider.new_resource).to equal(@resource)
  end

  context "cast git version into gem version object" do
    it "returns correct version with standard git" do
      expect(@provider).to receive(:shell_out!)
        .with("git --version", log_tag: "git[web2.0 app]")
        .and_return(double("ShellOut result", stdout: "git version 2.14.1"))
      expect(@provider.git_gem_version).to eq Gem::Version.new("2.14.1")
    end

    it "returns correct version with Apple git" do
      expect(@provider).to receive(:shell_out!)
        .with("git --version", log_tag: "git[web2.0 app]")
        .and_return(double("ShellOut result", stdout: "git version 2.11.0 (Apple Git-81)"))
      expect(@provider.git_gem_version).to eq Gem::Version.new("2.11.0")
    end

    it "maintains deprecated method name" do
      expect(@provider).to receive(:shell_out!)
        .with("git --version", log_tag: "git[web2.0 app]")
        .and_return(double("ShellOut result", stdout: "git version 1.2.3"))
      expect(@provider.git_minor_version).to eq Gem::Version.new("1.2.3")
    end

    it "does not know how to handle other version" do
      expect(@provider).to receive(:shell_out!)
        .with("git --version", log_tag: "git[web2.0 app]")
        .and_return(double("ShellOut result", stdout: "git version home-grown-git-99"))
      expect(@provider.git_gem_version).to be_nil
    end

    it "determines single branch option when it fails to parse git version" do
      expect(@provider).to receive(:shell_out!)
        .with("git --version", log_tag: "git[web2.0 app]")
        .and_return(double("ShellOut result", stdout: "git version home-grown-git-99"))
      expect(@provider.git_has_single_branch_option?).to be false
    end

    it "determines single branch option as true when it parses git version and version is large" do
      expect(@provider).to receive(:shell_out!)
        .with("git --version", log_tag: "git[web2.0 app]")
        .and_return(double("ShellOut result", stdout: "git version 1.8.0"))
      expect(@provider.git_has_single_branch_option?).to be true
    end

    it "determines single branch option as false when it parses git version and version is small" do
      expect(@provider).to receive(:shell_out!)
        .with("git --version", log_tag: "git[web2.0 app]")
        .and_return(double("ShellOut result", stdout: "git version 1.7.4"))
      expect(@provider.git_has_single_branch_option?).to be false
    end

    it "is compatible with git in travis" do
      expect(@provider.git_gem_version).to be > Gem::Version.new("1.0")
    end
  end

  context "resolving revisions to a SHA" do

    before do
      @git_ls_remote = "git ls-remote \"git://github.com/opscode/chef.git\" "
    end

    it "returns resource.revision as is if revision is already a full SHA" do
      expect(@provider.target_revision).to eql("d35af14d41ae22b19da05d7d03a0bafc321b244c")
    end

    it "converts resource.revision from a tag to a SHA" do
      @resource.revision "v1.0"
      @stdout = ("d03c22a5e41f5ae3193460cca044ed1435029f53\trefs/heads/0.8-alpha\n" +
                 "503c22a5e41f5ae3193460cca044ed1435029f53\trefs/heads/v1.0\n")
      expect(@provider).to receive(:shell_out!).with(@git_ls_remote + "\"v1.0*\"", { :log_tag => "git[web2.0 app]" }).and_return(double("ShellOut result", :stdout => @stdout))
      expect(@provider.target_revision).to eql("503c22a5e41f5ae3193460cca044ed1435029f53")
    end

    it "converts resource.revision from an annotated tag to the tagged SHA (not SHA of tag)" do
      @resource.revision "v1.0"
      @stdout = ("d03c22a5e41f5ae3193460cca044ed1435029f53\trefs/heads/0.8-alpha\n" +
                 "503c22a5e41f5ae3193460cca044ed1435029f53\trefs/heads/v1.0\n" +
                 "663c22a5e41f5ae3193460cca044ed1435029f53\trefs/heads/v1.0^{}\n")
      expect(@provider).to receive(:shell_out!).with(@git_ls_remote + "\"v1.0*\"", { :log_tag => "git[web2.0 app]" }).and_return(double("ShellOut result", :stdout => @stdout))
      expect(@provider.target_revision).to eql("663c22a5e41f5ae3193460cca044ed1435029f53")
    end

    it "converts resource.revision from a tag to a SHA using an exact match" do
      @resource.revision "v1.0"
      @stdout = ("d03c22a5e41f5ae3193460cca044ed1435029f53\trefs/heads/0.8-alpha\n" +
                 "663c22a5e41f5ae3193460cca044ed1435029f53\trefs/tags/releases/v1.0\n" +
                 "503c22a5e41f5ae3193460cca044ed1435029f53\trefs/tags/v1.0\n")
      expect(@provider).to receive(:shell_out!).with(@git_ls_remote + "\"v1.0*\"", { :log_tag => "git[web2.0 app]" }).and_return(double("ShellOut result", :stdout => @stdout))
      expect(@provider.target_revision).to eql("503c22a5e41f5ae3193460cca044ed1435029f53")
    end

    it "converts resource.revision from a tag to a SHA, matching tags first, then heads" do
      @resource.revision "v1.0"
      @stdout = ("d03c22a5e41f5ae3193460cca044ed1435029f53\trefs/heads/0.8-alpha\n" +
          "663c22a5e41f5ae3193460cca044ed1435029f53\trefs/tags/v1.0\n" +
          "503c22a5e41f5ae3193460cca044ed1435029f53\trefs/heads/v1.0\n")
      expect(@provider).to receive(:shell_out!).with(@git_ls_remote + "\"v1.0*\"", { :log_tag => "git[web2.0 app]" }).and_return(double("ShellOut result", :stdout => @stdout))
      expect(@provider.target_revision).to eql("663c22a5e41f5ae3193460cca044ed1435029f53")
    end

    it "converts resource.revision from a tag to a SHA, matching heads if no tags match" do
      @resource.revision "v1.0"
      @stdout = ("d03c22a5e41f5ae3193460cca044ed1435029f53\trefs/heads/0.8-alpha\n" +
          "663c22a5e41f5ae3193460cca044ed1435029f53\trefs/tags/v1.1\n" +
          "503c22a5e41f5ae3193460cca044ed1435029f53\trefs/heads/v1.0\n")
      expect(@provider).to receive(:shell_out!).with(@git_ls_remote + "\"v1.0*\"", { :log_tag => "git[web2.0 app]" }).and_return(double("ShellOut result", :stdout => @stdout))
      expect(@provider.target_revision).to eql("503c22a5e41f5ae3193460cca044ed1435029f53")
    end

    it "converts resource.revision from a tag to a SHA, matching tags first, then heads, then revision" do
      @resource.revision "refs/pulls/v1.0"
      @stdout = ("d03c22a5e41f5ae3193460cca044ed1435029f53\trefs/heads/0.8-alpha\n" +
          "663c22a5e41f5ae3193460cca044ed1435029f53\trefs/tags/v1.0\n" +
          "805c22a5e41f5ae3193460cca044ed1435029f53\trefs/pulls/v1.0\n" +
          "503c22a5e41f5ae3193460cca044ed1435029f53\trefs/heads/v1.0\n")
      expect(@provider).to receive(:shell_out!).with(@git_ls_remote + "\"refs/pulls/v1.0*\"", { :log_tag => "git[web2.0 app]" }).and_return(double("ShellOut result", :stdout => @stdout))
      expect(@provider.target_revision).to eql("805c22a5e41f5ae3193460cca044ed1435029f53")
    end

    it "converts resource.revision from a tag to a SHA, using full path if provided" do
      @resource.revision "refs/heads/v1.0"
      @stdout = ("d03c22a5e41f5ae3193460cca044ed1435029f53\trefs/heads/0.8-alpha\n" +
          "663c22a5e41f5ae3193460cca044ed1435029f53\trefs/tags/v1.0\n" +
          "503c22a5e41f5ae3193460cca044ed1435029f53\trefs/heads/v1.0\n")
      expect(@provider).to receive(:shell_out!).with(@git_ls_remote + "\"refs/heads/v1.0*\"", { :log_tag => "git[web2.0 app]" }).and_return(double("ShellOut result", :stdout => @stdout))
      expect(@provider.target_revision).to eql("503c22a5e41f5ae3193460cca044ed1435029f53")
    end

    it "raises an invalid remote reference error if you try to deploy from ``origin'' and assertions are run" do
      @resource.revision "origin/"
      @provider.action = :checkout
      @provider.define_resource_requirements
      allow(::File).to receive(:directory?).with(parent_dir).and_return(true)
      expect { @provider.process_resource_requirements }.to raise_error(Chef::Exceptions::InvalidRemoteGitReference)
    end

    it "raises an unresolvable git reference error if the revision can't be resolved to any revision and assertions are run" do
      @resource.revision "FAIL, that's the revision I want"
      @provider.action = :checkout
      expect(@provider).to receive(:shell_out!).and_return(double("ShellOut result", :stdout => "\n"))
      @provider.define_resource_requirements
      expect { @provider.process_resource_requirements }.to raise_error(Chef::Exceptions::UnresolvableGitReference)
    end

    it "does not raise an error if the revision can't be resolved when assertions are not run" do
      @resource.revision "FAIL, that's the revision I want"
      expect(@provider).to receive(:shell_out!).and_return(double("ShellOut result", :stdout => "\n"))
      expect(@provider.target_revision).to eq(nil)
    end

    it "does not raise an error when the revision is valid and assertions are run." do
      @resource.revision "0.8-alpha"
      @stdout = "503c22a5e41f5ae3193460cca044ed1435029f53\trefs/heads/0.8-alpha\n"
      expect(@provider).to receive(:shell_out!).with(@git_ls_remote + "\"0.8-alpha*\"", { :log_tag => "git[web2.0 app]" }).and_return(double("ShellOut result", :stdout => @stdout))
      @provider.action = :checkout
      allow(::File).to receive(:directory?).with(parent_dir).and_return(true)
      @provider.define_resource_requirements
      expect { @provider.process_resource_requirements }.not_to raise_error
    end

    it "gives the latest HEAD revision SHA if nothing is specified" do
      @stdout = <<-SHAS
28af684d8460ba4793eda3e7ac238c864a5d029a\tHEAD
503c22a5e41f5ae3193460cca044ed1435029f53\trefs/heads/0.8-alpha
28af684d8460ba4793eda3e7ac238c864a5d029a\trefs/heads/master
c44fe79bb5e36941ce799cee6b9de3a2ef89afee\trefs/tags/0.5.2
14534f0e0bf133dc9ff6dbe74f8a0c863ff3ac6d\trefs/tags/0.5.4
d36fddb4291341a1ff2ecc3c560494e398881354\trefs/tags/0.5.6
9e5ce9031cbee81015de680d010b603bce2dd15f\trefs/tags/0.6.0
9b4d8dc38dd471246e7cfb1c3c1ad14b0f2bee13\trefs/tags/0.6.2
014a69af1cdce619de82afaf6cdb4e6ac658fede\trefs/tags/0.7.0
fa8097ff666af3ce64761d8e1f1c2aa292a11378\trefs/tags/0.7.2
44f9be0b33ba5c10027ddb030a5b2f0faa3eeb8d\trefs/tags/0.7.4
d7b9957f67236fa54e660cc3ab45ffecd6e0ba38\trefs/tags/0.7.8
b7d19519a1c15f1c1a324e2683bd728b6198ce5a\trefs/tags/0.7.8^{}
ebc1b392fe7e8f0fbabc305c299b4d365d2b4d9b\trefs/tags/chef-server-package
SHAS
      @resource.revision ""
      expect(@provider).to receive(:shell_out!).with(@git_ls_remote + "\"HEAD\"", { :log_tag => "git[web2.0 app]" }).and_return(double("ShellOut result", :stdout => @stdout))
      expect(@provider.target_revision).to eql("28af684d8460ba4793eda3e7ac238c864a5d029a")
    end
  end

  it "responds to :revision_slug as an alias for target_revision" do
    expect(@provider).to respond_to(:revision_slug)
  end

  context "with an ssh wrapper" do
    let(:deploy_user)  { "deployNinja" }
    let(:wrapper)      { "do_it_this_way.sh" }
    let(:expected_cmd) { 'git clone "git://github.com/opscode/chef.git" "/my/deploy/dir"' }
    let(:default_options) do
      {
        :user => deploy_user,
        :environment => { "GIT_SSH" => wrapper, "HOME" => "/home/deployNinja" },
        :log_tag => "git[web2.0 app]",
      }
    end
    before do
      @resource.user deploy_user
      @resource.ssh_wrapper wrapper
      allow(Etc).to receive(:getpwnam).and_return(double("Struct::Passwd", :name => @resource.user, :dir => "/home/deployNinja"))
    end
    context "without a timeout set" do
      it "clones a repo with default git options" do
        expect(@provider).to receive(:shell_out!).with(expected_cmd, default_options)
        @provider.clone
      end
    end
    context "with a timeout set" do
      let (:seconds) { 10 }
      before { @resource.timeout(seconds) }
      it "clones a repo with amended git options" do
        expect(@provider).to receive(:shell_out!).with(expected_cmd, default_options.merge(:timeout => seconds))
        @provider.clone
      end
    end
    context "with a specific home" do
      let (:override_home) do
        { "HOME" => "/home/masterNinja" }
      end
      let(:overrided_options) do
        {
          :user => deploy_user,
          :environment => { "GIT_SSH" => wrapper, "HOME" => "/home/masterNinja" },
          :log_tag => "git[web2.0 app]",
        }
      end
      before do
        @resource.environment(override_home)
      end
      before { @resource.environment(override_home) }
      it "clones a repo with amended git options with specific home" do
        expect(@provider).to receive(:shell_out!).with(expected_cmd, overrided_options)
        @provider.clone
      end
    end
  end

  context "with a user id" do
    let(:deploy_user)  { 123 }
    let(:expected_cmd) { 'git clone "git://github.com/opscode/chef.git" "/my/deploy/dir"' }
    let(:default_options) do
      {
        :user => 123,
        :environment => { "HOME" => "/home/deployNinja" },
        :log_tag => "git[web2.0 app]",
      }
    end
    before do
      @resource.user deploy_user
      allow(Etc).to receive(:getpwuid).and_return(double("Struct::Passwd", :name => @resource.user, :dir => "/home/deployNinja"))
    end
    context "with a specific home" do
      let (:override_home) do
        { "HOME" => "/home/masterNinja" }
      end
      let(:overrided_options) do
        {
          :user => 123,
          :environment => { "HOME" => "/home/masterNinja" },
          :log_tag => "git[web2.0 app]",
        }
      end
      before do
        @resource.environment(override_home)
      end
      before { @resource.environment(override_home) }
      it "clones a repo with amended git options with specific home" do
        expect(@provider).to receive(:shell_out!).with(expected_cmd, hash_including(overrided_options))
        @provider.clone
      end
    end
  end

  it "runs a clone command with escaped destination" do
    @resource.user "deployNinja"
    allow(Etc).to receive(:getpwnam).and_return(double("Struct::Passwd", :name => @resource.user, :dir => "/home/deployNinja"))
    @resource.destination "/Application Support/with/space"
    @resource.ssh_wrapper "do_it_this_way.sh"
    expected_cmd = "git clone \"git://github.com/opscode/chef.git\" \"/Application Support/with/space\""
    expect(@provider).to receive(:shell_out!).with(expected_cmd, :user => "deployNinja",
                                                                 :log_tag => "git[web2.0 app]",
                                                                 :environment => { "HOME" => "/home/deployNinja",
                                                                                   "GIT_SSH" => "do_it_this_way.sh" })
    @provider.clone
  end

  it "compiles a clone command using --depth for shallow cloning" do
    @resource.depth 5
    expected_cmd = "git clone --depth 5 \"git://github.com/opscode/chef.git\" \"/my/deploy/dir\""
    version_response = double("shell_out")
    allow(version_response).to receive(:stdout) { "git version 1.7.9" }
    expect(@provider).to receive(:shell_out!).with("git --version",
                                               :log_tag => "git[web2.0 app]").and_return(version_response)
    expect(@provider).to receive(:shell_out!).with(expected_cmd, :log_tag => "git[web2.0 app]")
    @provider.clone
  end

  it "compiles a clone command using --no-single-branch for shallow cloning when git >= 1.7.10" do
    @resource.depth 5
    expected_cmd = "git clone --depth 5 --no-single-branch \"git://github.com/opscode/chef.git\" \"/my/deploy/dir\""
    version_response = double("shell_out")
    allow(version_response).to receive(:stdout) { "git version 1.7.10" }
    expect(@provider).to receive(:shell_out!).with("git --version",
                                               :log_tag => "git[web2.0 app]").and_return(version_response)
    expect(@provider).to receive(:shell_out!).with(expected_cmd, :log_tag => "git[web2.0 app]")
    @provider.clone
  end

  it "compiles a clone command with a remote other than ``origin''" do
    @resource.remote "opscode"
    expected_cmd = "git clone -o opscode \"git://github.com/opscode/chef.git\" \"/my/deploy/dir\""
    expect(@provider).to receive(:shell_out!).with(expected_cmd, :log_tag => "git[web2.0 app]")
    @provider.clone
  end

  it "runs a checkout command with default options" do
    expect(@provider).to receive(:shell_out!).with("git branch -f deploy d35af14d41ae22b19da05d7d03a0bafc321b244c", :cwd => repo_dir,
                                                                                                                    :log_tag => "git[web2.0 app]").ordered
    expect(@provider).to receive(:shell_out!).with("git checkout deploy", :cwd => repo_dir,
                                                                          :log_tag => "git[web2.0 app]").ordered
    @provider.checkout
  end

  it "runs an enable_submodule command" do
    @resource.enable_submodules true
    expected_cmd = "git submodule sync"
    expect(@provider).to receive(:shell_out!).with(expected_cmd, :cwd => repo_dir,
                                                                 :log_tag => "git[web2.0 app]")
    expected_cmd = "git submodule update --init --recursive"
    expect(@provider).to receive(:shell_out!).with(expected_cmd, :cwd => repo_dir, :log_tag => "git[web2.0 app]")
    @provider.enable_submodules
  end

  it "does nothing for enable_submodules if resource.enable_submodules #=> false" do
    expect(@provider).not_to receive(:shell_out!)
    @provider.enable_submodules
  end

  it "runs a sync command with default options" do
    expect(@provider).to receive(:setup_remote_tracking_branches).with(@resource.remote, @resource.repository)
    expected_cmd1 = "git fetch --prune origin"
    expect(@provider).to receive(:shell_out!).with(expected_cmd1, :cwd => repo_dir, :log_tag => "git[web2.0 app]")
    expected_cmd2 = "git fetch origin --tags"
    expect(@provider).to receive(:shell_out!).with(expected_cmd2, :cwd => repo_dir, :log_tag => "git[web2.0 app]")
    expected_cmd3 = "git reset --hard d35af14d41ae22b19da05d7d03a0bafc321b244c"
    expect(@provider).to receive(:shell_out!).with(expected_cmd3, :cwd => repo_dir, :log_tag => "git[web2.0 app]")
    @provider.fetch_updates
  end

  it "runs a sync command with the user and group specified in the resource" do
    @resource.user("whois")
    allow(Etc).to receive(:getpwnam).and_return(double("Struct::Passwd", :name => @resource.user, :dir => "/home/whois"))
    @resource.group("thisis")
    expect(@provider).to receive(:setup_remote_tracking_branches).with(@resource.remote, @resource.repository)

    expected_cmd1 = "git fetch --prune origin"
    expect(@provider).to receive(:shell_out!).with(expected_cmd1, :cwd => repo_dir,
                                                                  :user => "whois", :group => "thisis",
                                                                  :log_tag => "git[web2.0 app]",
                                                                  :environment => { "HOME" => "/home/whois" })
    expected_cmd2 = "git fetch origin --tags"
    expect(@provider).to receive(:shell_out!).with(expected_cmd2, :cwd => repo_dir,
                                                                  :user => "whois", :group => "thisis",
                                                                  :log_tag => "git[web2.0 app]",
                                                                  :environment => { "HOME" => "/home/whois" })
    expected_cmd3 = "git reset --hard d35af14d41ae22b19da05d7d03a0bafc321b244c"
    expect(@provider).to receive(:shell_out!).with(expected_cmd3, :cwd => repo_dir,
                                                                  :user => "whois", :group => "thisis",
                                                                  :log_tag => "git[web2.0 app]",
                                                                  :environment => { "HOME" => "/home/whois" })
    @provider.fetch_updates
  end

  it "configures remote tracking branches when remote is ``origin''" do
    @resource.remote "origin"
    expect(@provider).to receive(:setup_remote_tracking_branches).with(@resource.remote, @resource.repository)
    fetch_command1 = "git fetch --prune origin"
    expect(@provider).to receive(:shell_out!).with(fetch_command1, :cwd => repo_dir, :log_tag => "git[web2.0 app]")
    fetch_command2 = "git fetch origin --tags"
    expect(@provider).to receive(:shell_out!).with(fetch_command2, :cwd => repo_dir, :log_tag => "git[web2.0 app]")
    fetch_command3 = "git reset --hard d35af14d41ae22b19da05d7d03a0bafc321b244c"
    expect(@provider).to receive(:shell_out!).with(fetch_command3, :cwd => repo_dir, :log_tag => "git[web2.0 app]")
    @provider.fetch_updates
  end

  it "configures remote tracking branches when remote is not ``origin''" do
    @resource.remote "opscode"
    expect(@provider).to receive(:setup_remote_tracking_branches).with(@resource.remote, @resource.repository)
    fetch_command1 = "git fetch --prune opscode"
    expect(@provider).to receive(:shell_out!).with(fetch_command1, :cwd => repo_dir, :log_tag => "git[web2.0 app]")
    fetch_command2 = "git fetch opscode --tags"
    expect(@provider).to receive(:shell_out!).with(fetch_command2, :cwd => repo_dir, :log_tag => "git[web2.0 app]")
    fetch_command3 = "git reset --hard d35af14d41ae22b19da05d7d03a0bafc321b244c"
    expect(@provider).to receive(:shell_out!).with(fetch_command3, :cwd => repo_dir, :log_tag => "git[web2.0 app]")
    @provider.fetch_updates
  end

  context "configuring remote tracking branches" do

    it "checks if a remote with this name already exists" do
      command_response = double("shell_out")
      allow(command_response).to receive(:exitstatus) { 1 }
      expected_command = "git config --get remote.#{@resource.remote}.url"
      expect(@provider).to receive(:shell_out!).with(expected_command,
                                                 :cwd => repo_dir,
                                                 :log_tag => "git[web2.0 app]",
                                                 :returns => [0, 1, 2]).and_return(command_response)
      add_remote_command = "git remote add #{@resource.remote} #{@resource.repository}"
      expect(@provider).to receive(:shell_out!).with(add_remote_command,
                                                 :cwd => repo_dir,
                                                 :log_tag => "git[web2.0 app]")
      @provider.setup_remote_tracking_branches(@resource.remote, @resource.repository)
    end

    it "runs the config with the user and group specified in the resource" do
      @resource.user("whois")
      @resource.group("thisis")
      allow(Etc).to receive(:getpwnam).and_return(double("Struct::Passwd", :name => @resource.user, :dir => "/home/whois"))
      command_response = double("shell_out")
      allow(command_response).to receive(:exitstatus) { 1 }
      expected_command = "git config --get remote.#{@resource.remote}.url"
      expect(@provider).to receive(:shell_out!).with(expected_command,
                                                 :cwd => repo_dir,
                                                 :log_tag => "git[web2.0 app]",
                                                 :user => "whois",
                                                 :group => "thisis",
                                                 :environment => { "HOME" => "/home/whois" },
                                                 :returns => [0, 1, 2]).and_return(command_response)
      add_remote_command = "git remote add #{@resource.remote} #{@resource.repository}"
      expect(@provider).to receive(:shell_out!).with(add_remote_command,
                                                 :cwd => repo_dir,
                                                 :log_tag => "git[web2.0 app]",
                                                 :user => "whois",
                                                 :group => "thisis",
                                                 :environment => { "HOME" => "/home/whois" })
      @provider.setup_remote_tracking_branches(@resource.remote, @resource.repository)
    end

    describe "when a remote with a given name hasn't been configured yet" do
      it "adds a new remote " do
        command_response = double("shell_out")
        allow(command_response).to receive(:exitstatus) { 1 }
        check_remote_command = "git config --get remote.#{@resource.remote}.url"
        expect(@provider).to receive(:shell_out!).with(check_remote_command,
                                                   :cwd => repo_dir,
                                                   :log_tag => "git[web2.0 app]",
                                                   :returns => [0, 1, 2]).and_return(command_response)
        expected_command = "git remote add #{@resource.remote} #{@resource.repository}"
        expect(@provider).to receive(:shell_out!).with(expected_command,
                                                   :cwd => repo_dir,
                                                   :log_tag => "git[web2.0 app]")
        @provider.setup_remote_tracking_branches(@resource.remote, @resource.repository)
      end
    end

    describe "when a remote with a given name has already been configured" do
      it "updates remote url when the url is different" do
        command_response = double("shell_out")
        allow(command_response).to receive(:exitstatus) { 0 }
        allow(command_response).to receive(:stdout) { "some_other_url" }
        check_remote_command = "git config --get remote.#{@resource.remote}.url"
        expect(@provider).to receive(:shell_out!).with(check_remote_command,
                                                   :cwd => repo_dir,
                                                   :log_tag => "git[web2.0 app]",
                                                   :returns => [0, 1, 2]).and_return(command_response)
        expected_command = "git config --replace-all remote.#{@resource.remote}.url \"#{@resource.repository}\""
        expect(@provider).to receive(:shell_out!).with(expected_command,
                                                   :cwd => repo_dir,
                                                   :log_tag => "git[web2.0 app]")
        @provider.setup_remote_tracking_branches(@resource.remote, @resource.repository)
      end

      it "doesn't update remote url when the url is the same" do
        command_response = double("shell_out")
        allow(command_response).to receive(:exitstatus) { 0 }
        allow(command_response).to receive(:stdout) { @resource.repository }
        check_remote_command = "git config --get remote.#{@resource.remote}.url"
        expect(@provider).to receive(:shell_out!).with(check_remote_command,
                                                   :cwd => repo_dir,
                                                   :log_tag => "git[web2.0 app]",
                                                   :returns => [0, 1, 2]).and_return(command_response)
        unexpected_command = "git config --replace-all remote.#{@resource.remote}.url \"#{@resource.repository}\""
        expect(@provider).not_to receive(:shell_out!).with(unexpected_command,
                                                       :cwd => repo_dir,
                                                       :log_tag => "git[web2.0 app]")
        @provider.setup_remote_tracking_branches(@resource.remote, @resource.repository)
      end

      it "resets remote url when it has multiple values" do
        command_response = double("shell_out")
        allow(command_response).to receive(:exitstatus) { 2 }
        check_remote_command = "git config --get remote.#{@resource.remote}.url"
        expect(@provider).to receive(:shell_out!).with(check_remote_command,
                                                   :cwd => repo_dir,
                                                   :log_tag => "git[web2.0 app]",
                                                   :returns => [0, 1, 2]).and_return(command_response)
        expected_command = "git config --replace-all remote.#{@resource.remote}.url \"#{@resource.repository}\""
        expect(@provider).to receive(:shell_out!).with(expected_command,
                                                   :cwd => repo_dir,
                                                   :log_tag => "git[web2.0 app]")
        @provider.setup_remote_tracking_branches(@resource.remote, @resource.repository)
      end
    end
  end

  it "raises an error if the git clone command would fail because the enclosing directory doesn't exist" do
    allow(@provider).to receive(:shell_out!)
    expect { @provider.run_action(:sync) }.to raise_error(Chef::Exceptions::MissingParentDirectory)
  end

  it "does a checkout by cloning the repo and then enabling submodules" do
    # will be invoked in load_current_resource
    allow(::File).to receive(:exist?).with(repo_git_dir).and_return(false)

    allow(::File).to receive(:exist?).with(repo_dir).and_return(true)
    allow(::File).to receive(:directory?).with(parent_dir).and_return(true)
    allow(::Dir).to receive(:entries).with(repo_dir).and_return([".", ".."])
    expect(@provider).to receive(:clone)
    expect(@provider).to receive(:checkout)
    expect(@provider).to receive(:enable_submodules)
    @provider.run_action(:checkout)
    # Even though an actual run will cause an update to occur, the fact that we've stubbed out
    # the actions above will prevent updates from registering
    # @resource.should be_updated
  end

  it "does not call checkout if enable_checkout is false" do
    # will be invoked in load_current_resource
    allow(::File).to receive(:exist?).with(repo_git_dir).and_return(false)

    allow(::File).to receive(:exist?).with(repo_dir).and_return(true)
    allow(::File).to receive(:directory?).with(parent_dir).and_return(true)
    allow(::Dir).to receive(:entries).with(repo_dir).and_return([".", ".."])

    @resource.enable_checkout false
    expect(@provider).to receive(:clone)
    expect(@provider).not_to receive(:checkout)
    expect(@provider).to receive(:enable_submodules)
    @provider.run_action(:checkout)
  end

  # REGRESSION TEST: on some OSes, the entries from an empty directory will be listed as
  # ['..', '.'] but this shouldn't change the behavior
  it "does a checkout by cloning the repo and then enabling submodules when the directory entries are listed as %w{.. .}" do
    allow(::File).to receive(:exist?).with(repo_git_dir).and_return(false)
    allow(::File).to receive(:exist?).with(repo_dir).and_return(false)
    allow(::File).to receive(:directory?).with(parent_dir).and_return(true)
    allow(::Dir).to receive(:entries).with(repo_dir).and_return(["..", "."])
    expect(@provider).to receive(:clone)
    expect(@provider).to receive(:checkout)
    expect(@provider).to receive(:enable_submodules)
    expect(@provider).to receive(:add_remotes)
    @provider.run_action(:checkout)
   # @resource.should be_updated
  end

  describe "when a non-empty destination already exists and isn't a git repo" do
    before do
      # will be invoked in load_current_resource
      allow(::File).to receive(:directory?).with(parent_dir).and_return(true)
      allow(@provider).to receive(:existing_git_dir?).and_return(false)
      allow(@provider).to receive(:target_dir_non_existent_or_empty?).and_return(false)
    end

    it "fails to checkout" do
      expect { @provider.run_action(:checkout) }.to raise_error(Chef::Exceptions::DestinationAlreadyExists)
    end

    it "fails to sync" do
      expect { @provider.run_action(:sync) }.to raise_error(Chef::Exceptions::DestinationAlreadyExists)
    end
  end

  it "syncs the code by updating the source when the repo has already been checked out" do
    expect(::File).to receive(:exist?).with(repo_git_dir).and_return(true)
    allow(::File).to receive(:directory?).with(parent_dir).and_return(true)
    expect(@provider).to receive(:find_current_revision).exactly(1).and_return("d35af14d41ae22b19da05d7d03a0bafc321b244c")
    expect(@provider).not_to receive(:fetch_updates)
    expect(@provider).to receive(:add_remotes)
    @provider.run_action(:sync)
    expect(@resource).not_to be_updated
  end

  it "marks the resource as updated when the repo is updated and gets a new version" do
    expect(::File).to receive(:exist?).with(repo_git_dir).and_return(true)
    allow(::File).to receive(:directory?).with(parent_dir).and_return(true)
    # invoked twice - first time from load_current_resource
    expect(@provider).to receive(:find_current_revision).exactly(1).and_return("d35af14d41ae22b19da05d7d03a0bafc321b244c")
    allow(@provider).to receive(:target_revision).and_return("28af684d8460ba4793eda3e7ac238c864a5d029a")
    expect(@provider).to receive(:fetch_updates)
    expect(@provider).to receive(:enable_submodules)
    expect(@provider).to receive(:add_remotes)
    @provider.run_action(:sync)
   # @resource.should be_updated
  end

  it "does not fetch any updates if the remote revision matches the current revision" do
    expect(::File).to receive(:exist?).with(repo_git_dir).and_return(true)
    allow(::File).to receive(:directory?).with(parent_dir).and_return(true)
    allow(@provider).to receive(:find_current_revision).and_return("d35af14d41ae22b19da05d7d03a0bafc321b244c")
    allow(@provider).to receive(:target_revision).and_return("d35af14d41ae22b19da05d7d03a0bafc321b244c")
    expect(@provider).not_to receive(:fetch_updates)
    expect(@provider).to receive(:add_remotes)
    @provider.run_action(:sync)
    expect(@resource).not_to be_updated
  end

  it "clones the repo instead of fetching it if the deploy directory doesn't exist" do
    allow(::File).to receive(:directory?).with(parent_dir).and_return(true)
    allow(::File).to receive(:exist?).with(repo_dir).and_return(false)
    expect(::File).to receive(:exist?).with(repo_git_dir).at_least(:once).and_return(false)
    expect(@provider).to receive(:action_checkout)
    expect(@provider).not_to receive(:shell_out!)
    @provider.run_action(:sync)
   # @resource.should be_updated
  end

  it "clones the repo instead of fetching updates if the deploy directory is empty" do
    expect(::File).to receive(:exist?).with(repo_git_dir).at_least(:once).and_return(false)
    allow(::File).to receive(:exist?).with(repo_dir).and_return(false)
    allow(::File).to receive(:directory?).with(parent_dir).and_return(true)
    allow(::File).to receive(:directory?).with(repo_dir).and_return(true)
    allow(@provider).to receive(:sync_command).and_return("huzzah!")
    expect(@provider).to receive(:action_checkout)
    expect(@provider).not_to receive(:shell_out!).with("huzzah!", :cwd => repo_dir)
    @provider.run_action(:sync)
    #@resource.should be_updated
  end

  it "does an export by cloning the repo then removing the .git directory" do
    allow(::File).to receive(:directory?).with(parent_dir).and_return(true)
    expect(@provider).to receive(:action_checkout)
    expect(FileUtils).to receive(:rm_rf).with(@resource.destination + "/.git")
    @provider.run_action(:export)
    expect(@resource).to be_updated
  end

  describe "calling add_remotes" do
    it "adds a new remote for each entry in additional remotes hash" do
      @resource.additional_remotes({ :opscode => "opscode_repo_url",
                                     :another_repo => "some_other_repo_url" })
      allow(STDOUT).to receive(:tty?).and_return(false)
      command_response = double("shell_out")
      allow(command_response).to receive(:exitstatus) { 0 }
      @resource.additional_remotes.each_pair do |remote_name, remote_url|
        expect(@provider).to receive(:setup_remote_tracking_branches).with(remote_name, remote_url)
      end
      @provider.add_remotes
    end
  end

  describe "calling multiple_remotes?" do
    before(:each) do
      @command_response = double("shell_out")
    end

    describe "when check remote command returns with status 2" do
      it "returns true" do
        allow(@command_response).to receive(:exitstatus) { 2 }
        expect(@provider.multiple_remotes?(@command_response)).to be_truthy
      end
    end

    describe "when check remote command returns with status 0" do
      it "returns false" do
        allow(@command_response).to receive(:exitstatus) { 0 }
        expect(@provider.multiple_remotes?(@command_response)).to be_falsey
      end
    end

    describe "when check remote command returns with status 0" do
      it "returns false" do
        allow(@command_response).to receive(:exitstatus) { 1 }
        expect(@provider.multiple_remotes?(@command_response)).to be_falsey
      end
    end
  end

  describe "calling remote_matches?" do
    before(:each) do
      @command_response = double("shell_out")
    end

    describe "when output of the check remote command matches the repository url" do
      it "returns true" do
        allow(@command_response).to receive(:exitstatus) { 0 }
        allow(@command_response).to receive(:stdout) { @resource.repository }
        expect(@provider.remote_matches?(@resource.repository, @command_response)).to be_truthy
      end
    end

    describe "when output of the check remote command doesn't match the repository url" do
      it "returns false" do
        allow(@command_response).to receive(:exitstatus) { 0 }
        allow(@command_response).to receive(:stdout) { @resource.repository + "test" }
        expect(@provider.remote_matches?(@resource.repository, @command_response)).to be_falsey
      end
    end
  end
end
