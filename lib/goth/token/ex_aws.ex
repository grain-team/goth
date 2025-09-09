defmodule Goth.Token.ExAws do
  @moduledoc """
  AWS workload identity integration using ex_aws/ex_aws_sts.

  This module provides AWS workload identity federation support by leveraging
  the existing ex_aws and ex_aws_sts libraries for credential resolution and
  AWS API integration.

  ## Dependencies

  This functionality requires the following optional dependencies:
  - `ex_aws ~> 2.1`
  - `ex_aws_sts ~> 2.0`

  If these dependencies are not available, AWS workload identity federation
  will not be supported, but other Goth functionality remains unaffected.

  ## Credential Sources Supported

  Through ex_aws, this module automatically supports:
  - EC2 Instance Metadata Service (IMDSv1 and IMDSv2)
  - ECS Task Credentials
  - AWS Lambda execution role
  - Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, etc.)
  - AWS CLI config files (~/.aws/credentials, ~/.aws/config)
  - IAM roles and assume role chains
  """

  require Logger

  @doc """
  Generates a subject token for AWS workload identity federation.

  This creates a signed GetCallerIdentity request using ex_aws that can be
  exchanged with Google's STS for an access token.

  ## Parameters

  - `credential_source` - The credential source configuration from the workload identity config
  - `http_client` - HTTP client configuration (currently unused, ex_aws handles its own HTTP)

  ## Returns

  - `{:ok, subject_token}` - Base64-encoded signed request for Google STS
  - `{:error, reason}` - Error message, including missing dependencies
  """

  if Code.ensure_loaded?(ExAws) && Code.ensure_loaded?(ExAws.STS) do
    def generate_subject_token() do
      with {:ok, signed_request} <- build_signed_request() do
        {:ok, encode_for_google_sts(signed_request)}
      end
    end

    defp build_signed_request() do
      params = %{
        "Version" => "2011-06-15",
        "Action" => "GetCallerIdentity"
      }

      operation = %ExAws.Operation.Query{
        path: "/",
        params: params,
        service: :sts,
        action: :get_caller_identity
      }

      case ExAws.request(operation, http_client: Goth.Token.ExAws.RequestCapture) do
        {:ok, %{body: request_details}} ->
          {:ok, request_details}

        {:error, reason} ->
          {:error, reason}

        _ ->
          {:error, "Failed to build signed request"}
      end
    end

    defmodule RequestCapture do
      @behaviour ExAws.Request.HttpClient

      @impl ExAws.Request.HttpClient
      def request(method, url, body, headers, _http_opts) do
        request_details = %{
          method: method |> Atom.to_string() |> String.upcase(),
          url: url,
          headers: headers,
          body: body || ""
        }

        response = %{
          status_code: 200,
          headers: headers,
          body: request_details
        }

        {:ok, response}
      end
    end

    defp encode_for_google_sts(signed_request) do
      token_data = %{
        "url" => signed_request.url,
        "method" => signed_request.method,
        "headers" =>
          Enum.map(signed_request.headers, fn {key, value} ->
            %{"key" => key, "value" => value}
          end),
        "body" => Base.encode64(signed_request.body)
      }

      token_data
      |> Jason.encode!()
      |> Base.url_encode64(padding: false)
    end
  else
    def generate_subject_token(_credential_source, _http_client) do
      {:error, "ex_aws and ex_aws_sts dependencies are required for AWS workload identity federation"}
    end
  end
end
