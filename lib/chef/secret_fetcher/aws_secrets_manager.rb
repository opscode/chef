#
# Author:: Marc Paradise (<marc@chef.io>)
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

require_relative "base"
require "aws-sdk-secretsmanager"

class Chef
  # == Chef::SecretFetcher::AWSSecretsManager
  # A fetcher that fetches a secret from AWS Secrets Manager
  # In this initial iteration it defaults to authentication via instance profile.
  # It is possible to pass options that configure it to use alternative credentials.
  #
  # For configuration options see https://docs.aws.amazon.com/sdk-for-ruby/v3/api/Aws/SecretsManager/Client.html#initialize-instance_method
  #
  # Note that ~/.aws default and environment-based configurations are supported by default in the
  # ruby SDK.
  #
  # Usage Example:
  #
  # fetcher = SecretFetcher.for_service(:aws_secrets_manager, { region: "us-east-1" })
  # fetcher.fetch("secretkey1")
  class SecretFetcher
    class AWSSecretsManager < Base
      DEFAULT_AWS_OPTS = { }
      def validate!
        # Note that we are not doing any validation of required configuration here, we will
        # rely on the API client to do that for us, since it will work with the merge of
        # the config we provide, env-based config, and/or an appropriate profile in ~/.aws

        # Instantiating the client is an opportunity for an API provider to do validation,
        # so we'll do that first here.
        client
      end

      # @param identifier [String] the secret_id
      # @return Aws::SecretsManager::Types::GetSecretValueResponse
      def do_fetch(identifier)
        client.get_secret_value(secret_id: identifier)
      end

      def client
        @client ||= Aws::SecretsManager::Client.new(DEFAULT_AWS_OPTS.merge(config))
      end
    end
  end
end
