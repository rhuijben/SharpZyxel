using AmpScm.Buckets.Cryptography;
using Microsoft.Extensions.Options;
using System.Diagnostics;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SharpZyxel;

public class ZyxelClient : IDisposable
{
    HttpClient? _client;
    byte[]? _aesKey;
    string? _sessionKey;
    string? _loginLevel;
    string? _cookie;
    Uri _uri;
    string _username = "admin";
    string _password;

    public Uri Uri { get => _uri; init => _uri = value; }
    public string Username { get; init; }
    public string Password { get; init; }
    public IHttpClientFactory? HttpClientFactory { get; init; }
    public string? HttpClientName { get; init; }

    static readonly JsonSerializerOptions _jsOptions = new JsonSerializerOptions()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public bool IsAuthorized => _aesKey != null && !string.IsNullOrEmpty(_sessionKey) && !string.IsNullOrEmpty(_cookie);

    public async ValueTask ConnectAsync(CancellationToken cancellationToken = default)
    {
        if (IsAuthorized)
            return;

        string Username = this.Username;
        string Password = this.Password;

        if (string.IsNullOrWhiteSpace(Password))
        {
            string homeDirectory = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string authFilePath = Path.Combine(homeDirectory, ".zyxelauth.json");

            if (File.Exists(authFilePath))
            {
                string jsonContent = File.ReadAllText(authFilePath);
                var authData = JsonSerializer.Deserialize<AuthData>(jsonContent);

                if (authData is { })
                {
                    Username = authData.Username;
                    Password = authData.Password;
                    _uri ??= new Uri(authData.Uri);
                }
            }
        }

        if (_client == null)
        {
            _client = HttpClientFactory?.CreateClient(HttpClientName ?? Options.DefaultName) ?? new HttpClient(CreateHandler());
            _client.BaseAddress = Uri;
        }

        using var pkResponse = await _client.GetAsync("getRSAPublickKey", cancellationToken).ConfigureAwait(false);

        pkResponse.EnsureSuccessStatusCode();

        var pkContent = await pkResponse.Content.ReadFromJsonAsync<getRSAPublickKeyResponse>(cancellationToken);

        if (pkContent?.result?.Contains("SUCCESS", StringComparison.OrdinalIgnoreCase) != true || string.IsNullOrWhiteSpace(pkContent.RSAPublicKey))
        {
            throw new InvalidOperationException("Unable to fetch public key result");
        }

        if (!PublicKeySignature.TryParse(pkContent.RSAPublicKey, out var publicKey))
        {
            throw new InvalidOperationException("Unable to parse public key");
        }

        using var aes = Aes.Create();
        //aes.Key = Convert.FromBase64String("t1OGJ42juA8yvMwQAoFne4Tc4WnGygCBpO4jzdl3rXY=");

        byte[] aesKeyEncrypted;

        {
            var pkValues = publicKey.GetValues();
            using var rsa = RSA.Create();
            var rsaParams = new RSAParameters();
            rsaParams.Modulus = pkValues[0].ToByteArray(true, true);
            rsaParams.Exponent = pkValues[1].ToByteArray(true, true);
            rsa.KeySize = rsaParams.Modulus.Length * 8;

            rsa.ImportParameters(rsaParams);

            // yes, Zyxel expects us to encrypt the BASE64 version of the encryption key... WHY???
            aesKeyEncrypted = rsa.Encrypt(Encoding.UTF8.GetBytes(Convert.ToBase64String(aes.Key)), RSAEncryptionPadding.Pkcs1);
        }

        var content = JsonSerializer.SerializeToUtf8Bytes(new UserLoginRequest
        {
            Input_Account = Username,
            Input_Passwd = Convert.ToBase64String(Encoding.UTF8.GetBytes(Password)),
        }, _jsOptions);
        var ksr = new KeySetRequest
        {
            key = Convert.ToBase64String(aesKeyEncrypted),
            iv = Convert.ToBase64String(aes.IV.Concat(Enumerable.Range(0, 16).Select(x => (byte)x)).ToArray()),
            content = Convert.ToBase64String(aes.EncryptCbc(content, aes.IV, PaddingMode.PKCS7))
        };

        var loginResponse = await _client.PostAsJsonAsync("/UserLogin", ksr, _jsOptions, cancellationToken);

        if (!loginResponse.IsSuccessStatusCode)
        {
            throw new ZyxelException(await loginResponse.Content.ReadAsStringAsync(cancellationToken));
        }
        loginResponse.EnsureSuccessStatusCode();

        var loginResultData = await loginResponse.Content.ReadFromJsonAsync<StandardResponse>(cancellationToken);

        var resultData = aes.DecryptCbc(Convert.FromBase64String(loginResultData!.content!), Convert.FromBase64String(loginResultData.iv!).Take(16).ToArray());

        var r = JsonSerializer.Deserialize<UserLoginResponse>(resultData, _jsOptions);

        if (r?.result?.Contains("SUCCESS", StringComparison.OrdinalIgnoreCase) == true
            && loginResponse.Headers.GetValues("Set-Cookie")?.FirstOrDefault() is { } cookie
            && !string.IsNullOrWhiteSpace(cookie))
        {
            _cookie = cookie.Split(';')[0];
            _aesKey = aes.Key.ToArray();
            _sessionKey = r.sessionkey;
            _loginLevel = r.loginLevel;
            _client.DefaultRequestHeaders.Add("Cookie", _cookie);
        }
        else
            throw new ZyxelException("Invalid login response");
    }

    public void Dispose()
    {
        try
        {
            _client?.Dispose();
        }
        finally
        {
            _client = null;
        }
    }

    private HttpMessageHandler CreateHandler()
    {
        HttpClientHandler handler = new HttpClientHandler();
        handler.ServerCertificateCustomValidationCallback = (x, y, z, p) =>
        {
            return true;
        };

        return handler;
    }

    public async ValueTask<JsonDocument> ApiCallAsync(string path, CancellationToken cancellationToken = default)
    {
        await ConnectAsync();

        var r = await _client.GetAsync(path, cancellationToken);

        r.EnsureSuccessStatusCode();

        var wrapped = await r.Content.ReadFromJsonAsync<StandardResponse>(cancellationToken);

        using var aes = Aes.Create();
        aes.Key = _aesKey!;
        var resultData = aes.DecryptCbc(Convert.FromBase64String(wrapped!.content!), Convert.FromBase64String(wrapped.iv!).Take(16).ToArray());

        return JsonDocument.Parse(resultData, new JsonDocumentOptions() { });
    }

    public async ValueTask<TResult> ApiCallAsync<TResult>(string path, CancellationToken cancellationToken = default) where TResult : notnull
    {
        await ConnectAsync();

        var r = await _client.GetAsync(path, cancellationToken);

        r.EnsureSuccessStatusCode();

        var wrapped = await r.Content.ReadFromJsonAsync<StandardResponse>(cancellationToken);

        using var aes = Aes.Create();
        aes.Key = _aesKey!;
        var resultData = aes.DecryptCbc(Convert.FromBase64String(wrapped!.content!), Convert.FromBase64String(wrapped.iv!).Take(16).ToArray());

        var result = JsonSerializer.Deserialize<ApiResult<TResult>>(resultData, JsonSerializerOptions.Default);

        if (result?.result is "ZCFG_SUCCESS")
            return result.Object!;
        else
        {
            throw new ZyxelException($"{result?.result}: {result?.ReplyMsg}");
        }
    }

    public async Task<IEnumerable<LanHost>> GetLanHostsAsync(CancellationToken cancellationToken = default)
    {
        var doc = await ApiCallAsync<LanHostsResult[]>("/cgi-bin/DAL?oid=lanhosts");

        Debug.WriteLine(JsonSerializer.Serialize(doc, new JsonSerializerOptions()
        {
            WriteIndented = true
        }));

        return doc.SelectMany(x => x.lanhosts);
    }

    private record LanHostsResult : ReportAdditionalItems
    {
        public WanInfo wanInfo { get; init; } = new();
        public IEnumerable<LanHost> lanhosts { get; init; } = [];
    }

    private record WanInfo : ReportAdditionalItems
    {
        public int? wanStatus { get; init; }
        public int? wanIfaceExists { get; init; }
        public string? wanType { get; init; }
    }

    public record LanHost
    {
        public string? Alias { get; init; }
        // Mac address
        public string? PhysAddress { get; init; }
        public string? IPAddress { get; init; }
        public string? IPAddress6 { get; init; }
        public string? IPLinkLocalAddress6 { get; init; }
        public string? DHCPClient { get; init; }
        public int? LeaseTimeRemaining { get; init; }
        public string? AssociatedDevice { get; init; }
        public string? Layer1Interface { get; init; }
        public string? Layer3Interface { get; init; }
        public string? VendorClassID { get; init; }
        public string? ClientID { get; init; }
        public string? UserClassID { get; init; }
        public string? HostName { get; init; }
        public bool? Active { get; init; }
        public int? IPv4AddressNumberOfEntries { get; init; }
        public int? IPv6AddressNumberOfEntries { get; init; }
        public string? ClientDuid { get; init; }
        public string? ExpireTime { get; init; }
        public string? SupportedFrequencyBands { get; init; }
        public string? WifiName { get; init; }
        public string? DeviceSource { get; init; }
        public string? DeviceIcon { get; init; }
        public bool? Internet_Blocking_Enable { get; init; }
        public bool? BrowsingProtection { get; init; }
        public bool? TrackingProtection { get; init; }
        public bool? IOTProtection { get; init; }
        public string? Profile { get; init; }
        public string? SourceVendorClassID { get; init; }
        public string? DeviceName { get; init; }
        public string? curHostName { get; init; }
        public bool? dhcp4PoolExists { get; init; }
        public IEnumerable<int>? dhcp4PoolIid { get; init; }
        public bool? dhcp4StaticAddrExist { get; init; }

        public IEnumerable<int>? dhcp4StaticAddrIid { get; init; }
        public bool? dhcp4StaticAddrEnable { get; init; }
        public string? dhcp4StaticAddr { get; init; }
        public int? dhcp4StaticAddNum { get; init; }
        public bool? dhcp4StaticAddrUsedByOtherHost { get; init; }
        public string? icon { get; init; }
        public string? staticIP { get; init; }

        public string? X_ZYXEL_HostType { get; init; }
        public string? X_ZYXEL_ConnectionType { get; init; }
        public string? X_ZYXEL_OperatingStandard { get; init; }
        public decimal? X_ZYXEL_PhyRate { get; init; }
        public string? X_ZYXEL_Neighbor { get; init; }

        public decimal? X_ZYXEL_LastDataDownlinkRate { get; init; }
        public decimal? X_ZYXEL_LastDataUplinkRate { get; init; }
        public decimal? X_ZYXEL_SNR { get; init; }
        public int? X_ZYXEL_SignalStrength { get; init; }

        [JsonExtensionData]
        public IDictionary<string, JsonElement>? AdditionalData
        {
            get; init;
        }
    }

    private record ApiResult<TBody>
    {
        public string result { get; init; }
        public string? ReplyMsg { get; init; }
        public string? ReplyMsgMultiLang { get; init; }
        public TBody? Object { get; init; }
    }

    private record getRSAPublickKeyResponse
    {
        public string? RSAPublicKey { get; set; }
        public string? result { get; set; }
    }

    private record StandardRequest
    {
        public string? content { get; set; }
        public string? iv { get; set; }
    }

    private record KeySetRequest : StandardRequest
    {
        public string? key { get; set; }
    }

    private record StandardResponse
    {
        public string? content { get; set; }
        public string? iv { get; set; }
    }

    private record UserLoginRequest
    {
        public string? Input_Account { get; set; }
        public string? Input_Passwd { get; set; }
        public string? currLang { get; set; } = "en";
        public int RememberPassword { get; set; } = 0;
        public bool SHA512_password { get; set; } = false;
    }

    private record UserLoginResponse
    {
        public string? sessionkey { get; set; }
        public string? ThemColor { get; set; }
        public bool? changePw { get; set; }
        public bool? showSkipBtn { get; set; }
        public bool? quickStart { get; set; }
        public bool? quickStartEnabled { get; set; }
        public string? loginAccount { get; set; }
        public string? loginLevel { get; set; }
        public string? result { get; set; }
    }

    private abstract record ReportAdditionalItems
    {
        [JsonExtensionData]
        public IDictionary<string, JsonElement>? AdditionalData
        {
            get; init;
        }
    }

    private class AuthData
    {
        public string? Uri { get; set; }
        public string? Username { get; set; }
        public string? Password { get; set; }

    }
}