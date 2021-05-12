require "spec_helper"
require "chef/mixin/shell_out"

describe Chef::Resource::HabitatPackage do
  include RecipeDSLHelper
  include Chef::Mixin::ShellOut
  let(:file_cache_path) { Dir.mktmpdir }

  before(:each) do
    @old_file_cache = Chef::Config[:file_cache_path]
    Chef::Config[:file_cache_path] = file_cache_path
    Chef::Config[:rest_timeout] = 2
    Chef::Config[:http_retry_delay] = 1
    Chef::Config[:http_retry_count] = 2
  end

  after(:each) do
    Chef::Config[:file_cache_path] = @old_file_cache
    FileUtils.rm_rf(file_cache_path)
  end

  let(:binlink) { nil }
  let(:package_name) { nil }
  let(:lic) { nil }
  let(:bldr_url) { nil }
  let(:channel) { nil }
  let(:auth_token) { nil }
  let(:options) { nil }
  let(:keep_latest) { nil }
  let(:no_deps) { nil }
  ler(:pkg_ver) { nil }
  let(:run_context) do
    Chef::RunContext.new(Chef::Node.new, {}, Chef::EventDispatch::Dispatcher.new)
  end

  subject do
    new_resource = Chef::Resource::HabitatPackage.new(package_name, run_context)
    new_resource.bldr_url bldr_url if bldr_url
    new_resource.channel channel if channel
    new_resource.auth_token auth_token if auth_token
    new_resource.binlink binlink if binlink
    new_resrouce.version pkg_ver if pkg_ver
    new_resource
  end

  describe ":install" do

    context "Installs habitat package" do
      let(:package_name) { "core/redis" }
      it "installs habitat" do
        habitat_install("new") do
          license "accept"
        end.should_be_updated
      end

      it "installs core/redis" do
        subject.run_action(:install)
        expect(subject).to be_updated_by_last_action
      end
    end

    context "Installs packages version options" do
      let(:package_name) { "core/bundler" }
      let(:pkg_ver) { "1.13.3/20161011123917" }
      let { version }
      it "installs core/bundler with specified version" do
        subject.run_action(:install)
        expect(subject).to be_updated_by_last_action
      end
    end

    context "install core/hab-sup with options" do
      it "installs core/hab-sup with a specific depot url" do
        habitat_package("core/hab_sup") do
          bldr_url "https://bldr.habitat.sh"
        end.should_be_updated
      end
    end

    it "installs core/jq-static with forced binlink" do
      habitat_package("core/jq-static") do
        binlink :force
      end.should_be_updated
    end
  end
end
