#
# Author:: Marc Paradise <marc@chef.io>
# Copyright:: Copyright (c) Chef Software Inc.
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

require "chef/secret_fetcher"
require "chef/secret_fetcher/example"

class SecretFetcherImpl < Chef::SecretFetcher::Base
  def do_fetch(name)
    name
  end

  def validate!; end
end

describe Chef::SecretFetcher do
  let(:fetcher_impl) { SecretFetcherImpl.new({}) }

  before do
    allow(Chef::SecretFetcher::Example).to receive(:new).and_return fetcher_impl
  end

  context ".for_service" do
    it "resolves the example fetcher without error" do
      Chef::SecretFetcher.for_service(:example, {})
    end

    it "resolves the AWS fetcher without error" do
      Chef::SecretFetcher.for_service(:aws_secrets_manager, region: "invalid")
    end

    it "raises Chef::Exceptions::Secret::MissingFetcher when service is blank" do
      expect { Chef::SecretFetcher.for_service(nil, {}) }.to raise_error(Chef::Exceptions::Secret::MissingFetcher)
    end

    it "raises Chef::Exceptions::Secret::MissingFetcher when service is nil" do
      expect { Chef::SecretFetcher.for_service("", {}) }.to raise_error(Chef::Exceptions::Secret::MissingFetcher)
    end

    it "raises Chef::Exceptions::Secret::InvalidFetcher for an unknown fetcher" do
      expect { Chef::SecretFetcher.for_service(:bad_example, {}) }.to raise_error(Chef::Exceptions::Secret::InvalidFetcherService)
    end

    it "ensures fetcher configuration is valid by invoking validate!" do
      expect(fetcher_impl).to receive(:validate!)
      Chef::SecretFetcher.for_service(:example, {})
    end
  end

  context "#fetch" do
    let(:fetcher) {
      Chef::SecretFetcher.for_service(:example, { "key1" => "value1" })
    }

    it "fetches from the underlying service when secret name is provided " do
      expect(fetcher_impl).to receive(:fetch).with("key1")
      fetcher.fetch("key1")
    end

    it "raises an error when the secret name is not provided" do
      expect { fetcher.fetch(nil) }.to raise_error(Chef::Exceptions::Secret::MissingSecretName)
    end
  end
end
