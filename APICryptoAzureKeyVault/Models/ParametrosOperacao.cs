using System.ComponentModel.DataAnnotations;

namespace APICryptoAzureKeyVault.Models;

public class ParametrosOperacao
{
    [Required]
    public string? Key { get; set; }

    [Required]
    public string? Conteudo { get; set; }
}