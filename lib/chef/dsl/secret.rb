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
require_relative "../secret_fetcher"

class Chef
  module DSL
    module Secret

      # Helper method which looks up a secret using the given service and configuration,
      # and returns the retrieved secret value.
      # This DSL providers a wrapper around [Chef::SecretFetcher]
      #
      # @option name [Object] The identifier or name for this secret
      # @option service [Symbol] The service identifier for the service that will
      #                         perform the secret lookup
      # @option config [Hash] The configuration that the named service expects
      #
      # @return result [Object] The response object type is determined by the fetcher. See fetcher documentation
      # to know what to expect for a given service.
      #
      # @example
      #
      # This example uses the built-in :example secret manager service, which
      # accepts a hash of secrets.
      #
      #   value = secret(name: "test1", service: :example, config: { "test1" => "value1" })
      #   log "My secret is #{value}"
      #
      #   value = secret(name: "test1", service: :aws_secrets_manager, config: { region: "us-west-1" })
      #   log "My secret is #{value.secret_string}"
      #
      # @note
      #
      # This is pretty straightforward, but should also extend nicely to support
      # named config (as 'service') with override config. Some future potential
      # usage examples:
      #   value = secret(name: "test1") # If a default is configured
      #   value = secret(name: "test1", service: "my_aws_east")
      #   value = secret(name: "test1", service: "my_aws_west", config: { region: "override-region" })
      def secret(name: nil, service: nil, config: nil)
        Chef::SecretFetcher.for_service(service, config).fetch(name)
      end
    end
  end
end


