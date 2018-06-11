defmodule ExHMACTest do
  require Logger
  use ExUnit.Case
  import Mock
  doctest ExHMAC

  @key "some-api-key"
  @secret "much secret"

  test "it adds api_key to urls as a query paramter" do
    url = "http://example.com"

    %{url: new_url} = ExHMAC.prepare(url, @key, @secret)

    assert new_url == "http://example.com?apiKey=some-api-key"
  end

  test "it adds api_key to urls as a query paramter after all previous params" do
    url = "http://example.com?wat=nothing"

    %{url: new_url} = ExHMAC.prepare(url, @key, @secret)

    assert new_url == "http://example.com?wat=nothing&apiKey=some-api-key"
  end

  test "it adds a timestamp header" do
    url = "http://example.com"

    with_mock ExHMAC, [:passthrough], [timestamp: fn () -> {1426, 90432, 975884} end] do
      %{headers: headers} = ExHMAC.prepare(url, @key, @secret)
      assert Map.get(headers, "X-Auth-Timestamp") == "2015-03-11T16:13:52.975884+00:00"
    end
  end

  test "when previous headers are provided, it adds timestamp to them" do
    url = "http://example.com"
    headers = %{"content-type" => "application/json"}

    with_mock ExHMAC, [:passthrough], [timestamp: fn () -> {1426, 90432, 975884} end] do
      %{headers: new_headers} = ExHMAC.prepare(url, headers, @key, @secret)

      assert Map.get(new_headers, "content-type") == "application/json"
      assert Map.get(new_headers, "X-Auth-Timestamp") == "2015-03-11T16:13:52.975884+00:00"

      %{headers: new_headers2} = ExHMAC.prepare(:get, url, headers, @key, @secret)
      assert Map.get(new_headers2, "content-type") == "application/json"
      assert Map.get(new_headers2, "X-Auth-Timestamp") == "2015-03-11T16:13:52.975884+00:00"
    end
  end

  test "it adds signature header for get requests" do
    url = "http://example.com?wat=nothing"

    with_mock ExHMAC, [:passthrough], [timestamp: fn () -> {1426, 90432, 975884} end] do
      %{headers: headers} = ExHMAC.prepare(url, @key, @secret)
      assert Map.get(headers, "X-Auth-Signature") == "46ukTg5FFU0vMVaxXdjoHHAm3qz651A8ZtLVsMlW9LE="
    end
  end

  test "it adds a correct signature headers for requests with content" do
    url = "http://example.com?wat=noting"
    content = "content"
    headers = %{"content-type" => "application/json"}

    with_mock ExHMAC, [:passthrough], [timestamp: fn () -> {1426, 90432, 975884} end] do
      %{headers: new_headers} = ExHMAC.prepare(:post, url, headers, content, @key, @secret)
      assert Map.get(new_headers, "X-Auth-Signature") == "O1Z81eBIzn9WJkt-oGlMrrq2-TE8CwEZMtpwqoGsXpY="
    end
  end

  test "it validates signature" do
    url = "http://example.com?wat=noting"
    content = "content"
    headers = %{"content-type" => "application/json"}

    %{headers: headers, url: new_url} = ExHMAC.prepare(:post, url, headers, content, @key, @secret)
    {:ok, ts} = Map.fetch(headers, "X-Auth-Timestamp")
    {:ok, signature} = Map.fetch(headers, "X-Auth-Signature")
    assert ExHMAC.validate_signature(signature, :post, new_url, content, ts, @secret)
  end

  test "it invalidates provided signature when timestamp changed" do
    url = "http://example.com?wat=noting"
    content = "content"
    headers = %{"content-type" => "application/json"}

    %{headers: headers, url: new_url} = ExHMAC.prepare(:post, url, headers, content, @key, @secret)
    ts = "2015-03-11T16:13:52.975884+00:00"
    {:ok, signature} = Map.fetch(headers, "X-Auth-Signature")
    refute ExHMAC.validate_signature(signature, :post, new_url, content, ts, @secret)
  end

  test "it invalidates provided signature when payload changed" do
    url = "http://example.com?wat=noting"
    content = "content"
    headers = %{"content-type" => "application/json"}

    %{headers: headers, url: new_url} = ExHMAC.prepare(:post, url, headers, content, @key, @secret)
    {:ok, ts} = Map.fetch(headers, "X-Auth-Timestamp")
    {:ok, signature} = Map.fetch(headers, "X-Auth-Signature")
    refute ExHMAC.validate_signature(signature, :post, new_url, "Content", ts, @secret)
  end

  test "it invalidates provided signature when url changed" do
    url = "http://example.com?wat=noting"
    content = "content"
    headers = %{"content-type" => "application/json"}

    %{headers: headers} = ExHMAC.prepare(:post, url, headers, content, @key, @secret)
    {:ok, ts} = Map.fetch(headers, "X-Auth-Timestamp")
    {:ok, signature} = Map.fetch(headers, "X-Auth-Signature")
    refute ExHMAC.validate_signature(signature, :post, url, content, ts, @secret)
  end

  test "it invalidates provided signature when method changed" do
    url = "http://example.com?wat=noting"
    content = "content"
    headers = %{"content-type" => "application/json"}

    %{headers: headers} = ExHMAC.prepare(:post, url, headers, content, @key, @secret)
    {:ok, ts} = Map.fetch(headers, "X-Auth-Timestamp")
    {:ok, signature} = Map.fetch(headers, "X-Auth-Signature")
    refute ExHMAC.validate_signature(signature, :get, url, content, ts, @secret)
  end

  test "it invalidates provided signature when secret changed" do
    url = "http://example.com?wat=noting"
    content = "content"
    headers = %{"content-type" => "application/json"}

    %{headers: headers, url: new_url} = ExHMAC.prepare(:post, url, headers, content, @key, @secret)
    {:ok, ts} = Map.fetch(headers, "X-Auth-Timestamp")
    {:ok, signature} = Map.fetch(headers, "X-Auth-Signature")
    refute ExHMAC.validate_signature(signature, :post, new_url, content, ts, "different_secret")
  end

end
