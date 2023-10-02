using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.Text;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using APICryptoAzureKeyVault.Models;

namespace APICryptoAzureKeyVault.Controllers;

[ApiController]
[Route("[controller]")]
public class TestsKeyVaultController : ControllerBase
{
    private readonly ILogger<TestsKeyVaultController> _logger;
    private readonly KeyClient _keyClient;

    public TestsKeyVaultController(ILogger<TestsKeyVaultController> logger,
        IConfiguration configuration)
    {
        _logger = logger;

        _logger.LogInformation("Gerando o objeto KeyClient...");
        _keyClient = new KeyClient(new Uri(configuration["AzureKeyVaultURI"]!),
            new DefaultAzureCredential());
    }

    [HttpPost("Encriptar")]
    [ProducesResponseType(typeof(Resultado), (int)HttpStatusCode.OK)]
    [ProducesResponseType((int)HttpStatusCode.BadRequest)]
    public async Task<Resultado> PostEncriptar(ParametrosOperacao dados)
    {
        _logger.LogInformation("Obtendo Key...");
        var key = await _keyClient.GetKeyAsync(dados.Key);

        _logger.LogInformation("Gerando o objeto CryptographyClient...");
        var cryptoClient = new CryptographyClient(key.Value.Id, new DefaultAzureCredential());

        _logger.LogInformation("Iniciando encriptacao...");
        var encryptResult = await cryptoClient.EncryptAsync(
            EncryptionAlgorithm.RsaOaep,
            Encoding.UTF8.GetBytes(dados.Conteudo!));
        _logger.LogInformation("Encriptação concluida...");

        return new()
        {
            Operation = nameof(PostEncriptar),
            ConteudoOriginal = dados.Conteudo,
            ConteudoProcessado = Convert.ToBase64String(encryptResult.Ciphertext)
        };
    }

    [HttpPost("Decriptar")]
    [ProducesResponseType(typeof(Resultado), (int)HttpStatusCode.OK)]
    [ProducesResponseType((int)HttpStatusCode.BadRequest)]
    public async Task<Resultado> PostDecriptar(ParametrosOperacao dados)
    {
        _logger.LogInformation("Obtendo Key...");
        var key = await _keyClient.GetKeyAsync(dados.Key);

        _logger.LogInformation("Gerando o objeto CryptographyClient...");
        var cryptoClient = new CryptographyClient(key.Value.Id, new DefaultAzureCredential());

        _logger.LogInformation("Iniciando decriptacao...");
        var decryptResult = await cryptoClient.DecryptAsync(
            EncryptionAlgorithm.RsaOaep,
            Convert.FromBase64String(dados.Conteudo!));
        _logger.LogInformation("Decriptacao concluida...");

        return new()
        {
            Operation = nameof(PostDecriptar),
            ConteudoOriginal = dados.Conteudo,
            ConteudoProcessado = Encoding.Default.GetString(decryptResult!.Plaintext)
        };
    }
}