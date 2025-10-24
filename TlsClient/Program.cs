using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

internal class SecureClient
{
    public static async Task Main(string[] args)
    {
        // Підключаємося до сервера на localhost, порт 8888
        var client = new TcpClient("localhost", 8888);
        Console.WriteLine("Під'єднано до сервера.");

    
        using (var sslStream = new SslStream(
                   client.GetStream(),
                   false,
                   ValidateServerCertificate,
                   null))
        {
            try
            {
                 
                await sslStream.AuthenticateAsClientAsync("localhost");
                Console.WriteLine("TLS-сесію встановлено з сервером.");

                // Документуємо параметри з'єднання
                DocumentSessionDetails(sslStream);

                using (var reader = new StreamReader(sslStream, Encoding.UTF8))
                using (var writer = new StreamWriter(sslStream, Encoding.UTF8) { AutoFlush = true })
                {
                    // 1. Очікуємо привітання від сервера
                    Console.WriteLine($"Сервер каже: {await reader.ReadLineAsync()}");

                    // 2. Надсилаємо дані для автентифікації
                    Console.Write("Введіть ім'я користувача: ");
                    var username = Console.ReadLine();
                    Console.Write("Введіть пароль: ");
                    var password = Console.ReadLine();
                    await writer.WriteLineAsync($"{username}:{password}");

                    // 3. Перевіряємо відповідь сервера
                    var authResponse = await reader.ReadLineAsync();
                    Console.WriteLine($"Відповідь сервера на автентифікацію: {authResponse}");

                    if (authResponse == "AUTH_SUCCESS")
                    {
                        Console.WriteLine("Автентифікація успішна!");

                        // 4. Надсилаємо повідомлення
                        Console.WriteLine(
                            $"Сервер каже: {await reader.ReadLineAsync()}");  
                        Console.Write("Введіть повідомлення для відправки: ");
                        var message = Console.ReadLine();
                        await writer.WriteLineAsync(message);

                        // 5. Отримуємо фінальну відповідь
                        var serverFinalResponse = await reader.ReadLineAsync();
                        Console.WriteLine($"Фінальна відповідь сервера: {serverFinalResponse}");
                    }
                    else
                    {
                        Console.WriteLine("Автентифікація не вдалася. Закриття з'єднання.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Сталася помилка: {ex.Message}");
            }
            finally
            {
                client.Close();
                Console.WriteLine("З'єднання закрито.");
            }
        }
    }

    // Цей метод викликається для перевірки сертифіката сервера.
    // Оскільки я використовую самопідписаний сертифікат, стандартна перевірка не пройде.
    // Ігноруємо помилку, АЛЕ ЦЕ НЕБЕЗПЕЧНО для реальних застосунків.
    private static bool ValidateServerCertificate(
        object sender,
        X509Certificate certificate,
        X509Chain chain,
        SslPolicyErrors sslPolicyErrors)
    {
        if (sslPolicyErrors == SslPolicyErrors.None)
        {
            Console.WriteLine("Сертифікат сервера дійсний.");
            return true;
        }

        
        Console.WriteLine($"Помилка сертифіката: {sslPolicyErrors}. Приймаємо для демонстраційних цілей.");
        return true;
    }

    private static void DocumentSessionDetails(SslStream sslStream)
    {
        Console.WriteLine("\n--- Деталі зашифрованої сесії ---");
        Console.WriteLine($"Протокол: {sslStream.SslProtocol}");
        Console.WriteLine($"Алгоритм шифрування: {sslStream.CipherAlgorithm} ({sslStream.CipherStrength} біт)");
        Console.WriteLine($"Алгоритм хешування: {sslStream.HashAlgorithm} ({sslStream.HashStrength} біт)");
        Console.WriteLine(
            $"Алгоритм обміну ключами: {sslStream.KeyExchangeAlgorithm} ({sslStream.KeyExchangeStrength} біт)");

        var remoteCert = sslStream.RemoteCertificate;
        if (remoteCert != null)
        {
            Console.WriteLine("\n--- Інформація про сертифікат сервера ---");
            Console.WriteLine($"Тема (Subject): {remoteCert.Subject}");
            Console.WriteLine($"Видавець (Issuer): {remoteCert.Issuer}");
            Console.WriteLine($"Дійсний з: {((X509Certificate2)remoteCert).NotBefore}");
            Console.WriteLine($"Дійсний до: {((X509Certificate2)remoteCert).NotAfter}");
            Console.WriteLine($"Відбиток (Thumbprint): {((X509Certificate2)remoteCert).Thumbprint}");
            Console.WriteLine("----------------------------------\n");
        }
    }
}