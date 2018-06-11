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

  def prepare(method, url, headers, api_key, secret) do
    prepare(method, url, headers, "", api_key, secret)
  end

  def prepare(method, url, headers, content, api_key, secret) when is_binary(content) do
    ts = formatted_timestamp()
    new_url = append_api_key url, api_key
    %{
      url: new_url,
      headers:
        headers
        |> add_timestamp_header(ts)
        |> add_signature_header(method, new_url, content, ts, secret)
    }
  end

  def validate_signature(signature, method, url, content, ts, secret) do
    data = prepare_signature_data(method, url, content, ts)
    signature(data, secret) == signature
  end

  defp append_api_key(url, api_key) do
    separator = case URI.parse url do
      %{query: nil} -> "?"
      %{query: _q} -> "&"
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

    ts
    |> :calendar.now_to_datetime()
    |> Timex.to_datetime(:utc)
    |> Timex.add(Timex.Duration.from_microseconds(micro))
    |> Timex.format!("{ISO:Extended}")
  end

  defp add_signature_header(headers, method, url, content, ts, secret) do
    data = prepare_signature_data(method, url, content, ts)
    Map.put(headers, @signature_http_header, signature(data, secret))
  end

  defp prepare_signature_data(method, url, content, ts) do
    %{query: query, path: path} = URI.parse url
    path_url = "#{path}?#{query}"
    case String.length(content) do
      0 ->
        Enum.join [String.upcase(to_string(method)), ts, path_url], @signature_delimiter
      _ ->
        Enum.join [String.upcase(to_string(method)), ts, path_url, content], @signature_delimiter
    end
  end

  defp signature(data, secret) do
    digest = :crypto.hmac(:sha256, to_char_list(secret), to_char_list(data))
    digest |> :base64.encode |> String.replace("+", "-") |> String.replace("/", "_")
  end
end
