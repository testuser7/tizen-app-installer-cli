using ConsolePasswordMasker.Core;
using Spectre.Console;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TizenAppInstallerCli;

public class CertificateFile
{
    public async Task<(X509Certificate2Collection authorCerts, X509Certificate2Collection distributorCerts)>
    ReadCertificate()
    {
        AnsiConsole.MarkupLine($"[bold]Select author .p12 file[/]");
        X509Certificate2Collection authorCerts = ReadCertFile();

        AnsiConsole.MarkupLine($"[bold]Select distributor .p12 file[/]");
        X509Certificate2Collection distributorCerts = ReadCertFile();

        return (authorCerts, distributorCerts);
    }

    private X509Certificate2Collection ReadCertFile()
    {
        X509Certificate2Collection certPfx = null;
        string? certPath = FilePicker.PickFile(allowedExtensions: [".p12"]);

        if (certPath == null)
        {
            AnsiConsole.MarkupLine("[bold green]No file selected[/]");
        }
        else
        {
            string certPass = string.Empty;
            PasswordMasker masker = new PasswordMasker();

            while (certPfx == null)
            {
                try
                {
                    certPfx = X509CertificateLoader.LoadPkcs12CollectionFromFile(certPath, certPass);
                }
                catch (CryptographicException)
                {
                    certPass = masker.Mask("Certificate password: ");
                }
            }

            AnsiConsole.MarkupLineInterpolated($"Certificate selected: [bold green]{certPath}[/]");
        }
        return certPfx;
    }
}