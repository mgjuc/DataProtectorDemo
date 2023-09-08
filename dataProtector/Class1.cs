using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.DependencyInjection;
using System.Diagnostics;
using YIRI.Security;

public class Program
{
    public static void Main(string[] args)
    {
        string appname = "YIRITECH_APP";
        Console.WriteLine(Path.Combine(Environment.CurrentDirectory, "DataProtection-Keys"));
        // add data protection services
        var serviceCollection = new ServiceCollection();
        serviceCollection.Configure<KeyManagementOptions>(opt => opt.XmlEncryptor = new AesXmlEncryptor());
        serviceCollection.AddDataProtection()
            .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(Environment.CurrentDirectory, "DataProtection-Keys")))
            .SetApplicationName(appname)
            .SetDefaultKeyLifetime(TimeSpan.FromDays(365));

        var services = serviceCollection.BuildServiceProvider();

        // create an instance of MyClass using the service provider
        var instance = ActivatorUtilities.CreateInstance<MyClass>(services);
        instance.RunSample();
    }

    public class MyClass
    {
        IDataProtector _protector;
        string purpose = "YIRI.Security.Purpose.SensitiveDataPurpose"; 

        // the 'provider' parameter is provided by DI
        public MyClass(IDataProtectionProvider provider)
        {
            _protector = provider.CreateProtector(purpose);

        }

        public void RunSample()
        {
            try
            {
                string input = "6a7be2fee9bb-2023/09/08 15:07:41-2024/09/08 23:59:59";
                string sec = "CfDJ8Jevqcuq1MxNsuygwP_cBmy-OWX0odZblhpIIVTrE_vkZAW3Scc1jyFSzrBQhFVuPwZ37IOQd02WqPKIDNE64MeW_0FHx_8YfgMdqnfow7cyn_p4-N-8Vq10tvmicmdEIT2HG-1NKMNurgkIFXuc--9OGBVWKKJ48nVmSAXcf1aM_QJNJtihBebETYTVFyB75g";
                Console.WriteLine($"Enter input: {input}");

                // protect the payload
                string protectedPayload = _protector.Protect(input);
                Console.WriteLine($"Protect returned: {protectedPayload}");

                // unprotect the payload
                string unprotectedPayload = _protector.Unprotect(protectedPayload);
                Console.WriteLine($"Unprotect returned: {unprotectedPayload}");
                Debug.Assert(input == unprotectedPayload);

                //加密结果会不一样，但是仍可以解密的
                Console.WriteLine("解密：");
                Console.WriteLine(_protector.Unprotect(sec));
                Console.ReadKey();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }

        }
    }
}

/*
 * SAMPLE OUTPUT
 *
 * Enter input: Hello world!
 * Protect returned: CfDJ8ICcgQwZZhlAlTZT...OdfH66i1PnGmpCR5e441xQ
 * Unprotect returned: Hello world!
 */