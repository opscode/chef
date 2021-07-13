require_relative "base"

class Chef
  class SecretFetcher
    class AzureKeyVault < Base
      TOKEN_URL = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net".freeze

      def validate!
        @vault = config[:vault]
        if @vault.nil?
          raise Chef::Exceptions::Secret::MissingVaultName.new("You must provide a vault name to service options as vault: 'vault_name'")
        end
        @version = config[:version]
      end

      def do_fetch(identifier)
        token = fetch_token
        # Note that if `version` is never set, then it will not be appended to the URL; but if it is present
        # the  azure key-vault API will honor it
        secret_uri = URI.parse("https://#{@vault}.vault.azure.net/secrets/#{identifier}/#{version}?api-version=7.2")
        http = Net::HTTP.new(secret_uri.host, secret_uri.port)
        http.use_ssl = true
        response = http.get(secret_uri, { 'Authorization' => "Bearer #{token}",
                                          'Content-Type' => 'application/json' })
        result = JSON.parse(response.body)
        if result.key? "value"
          result["value"]
        else
          raise Chef::Secrets::FetchFailed.new("#{result["error"]["code"]}: #{result["error"]["message"]}")
        end
      end

      def fetch_token
        token_uri = URI.parse(TOKEN_URL)
        http = Net::HTTP.new(token_uri.host, token_uri.port)
        response = http.get(token_uri, { "Metadata" => "true"})
        body = JSON.parse(response.body)
        body["access_token"]
      end
    end
  end
end



