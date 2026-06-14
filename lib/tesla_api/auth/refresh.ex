defmodule TeslaApi.Auth.Refresh do
  import TeslaApi.Auth, only: [post: 2]

  alias TeslaApi.{Auth, Error}

  @web_client_id TeslaApi.Auth.web_client_id()

  def refresh(%Auth{} = auth) do
    issuer_url =
      if System.get_env("TESLA_AUTH_HOST", "") == "" do
        auth
        |> Auth.issuer_url()
        |> strip_nts_suffix()
      else
        System.get_env("TESLA_AUTH_HOST", "") <>
          System.get_env("TESLA_AUTH_PATH", "/oauth2/v3")
      end

    client_id = System.get_env("TESLA_AUTH_CLIENT_ID", @web_client_id)

    scope =
      if client_id != @web_client_id do
        "openid email offline_access vehicle_device_data vehicle_cmds vehicle_charging_cmds"
      else
        "openid email offline_access"
      end

    data = %{
      grant_type: "refresh_token",
      scope: scope,
      client_id: client_id,
      refresh_token: auth.refresh_token
    }

    case post(
           "#{issuer_url}/token" <> System.get_env("TOKEN", ""),
           data
         ) do
      {:ok, %Tesla.Env{status: 200, body: body}} ->
        auth = %Auth{
          token: body["access_token"],
          type: body["token_type"],
          expires_in: body["expires_in"],
          refresh_token: body["refresh_token"],
          created_at: body["created_at"]
        }

        {:ok, auth}

      error ->
        Error.into(error, :token_refresh)
    end
  end

  # Fleet API JWT tokens have issuer like "https://auth.tesla.com/oauth2/v3/nts"
  # The actual token endpoint is at "/oauth2/v3/token", not "/oauth2/v3/nts/token"
  defp strip_nts_suffix(url) do
    String.replace_suffix(url, "/nts", "")
  end
end
