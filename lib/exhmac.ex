defmodule ExHMAC do

  @api_key_query_param "apiKey"
  @timestamp_http_header "X-Auth-Timestamp"
  @signature_http_header "X-Auth-Signature"
  @signature_delimiter "\n"

  def prepare(url, api_key, secret) do
    prepare url, %{}, api_key, secret
  end

  def prepare(url, headers, api_key, secret) do
    prepare(:get, url, headers, "", api_key, secret)
  end
  def prepare(method, url, headers, content, api_key, secret) when is_binary(content) do
    ts = formatted_timestamp
    new_url = append_api_key url, api_key
    %{
      url: new_url,
      headers:
        headers
        |> add_timestamp_header(ts)
        |> add_signature_header(:get, new_url, content, ts, secret)
    }
  end

  defp append_api_key(url, api_key) do
    case URI.parse url do
      %{query: nil} -> separator = "?"
      %{query: _q} -> separator = "&"
    end
    url <> separator <> @api_key_query_param <> "=" <> api_key
  end

  defp add_timestamp_header(headers, ts) do
    Map.put headers, @timestamp_http_header, ts
  end

  def timestamp do
    :os.timestamp
  end

  defp formatted_timestamp do
    ts = ExHMAC.timestamp
    {_, _, micro} = ts
    ut = Timex.Date.construct :calendar.now_to_datetime(ts), Timex.Date.timezone(:utc)
    Timex.DateFormat.format!(%{ut | ms: micro}, "{ISO}")
  end

  defp add_signature_header(headers, method, url, content, ts, secret) do
    %{query: query, path: path} = URI.parse url
    path_url = "#{path}?#{query}"
    case String.length(content) do
      0 ->
        data_to_sign = Enum.join [String.upcase(to_string(method)), ts, path_url], @signature_delimiter
      _ ->
        data_to_sign = Enum.join [String.upcase(to_string(method)), ts, path_url, content], @signature_delimiter
    end
    Map.put(headers, @signature_http_header, signature(data_to_sign, secret))
  end

  defp signature(data, secret) do
    digest = :crypto.hmac(:sha256, to_char_list(secret), to_char_list(data))
    digest |> :base64.encode |> String.replace("+", "-") |> String.replace("/", "_")
  end
end
