using System;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using Microsoft.Extensions.Configuration;

class SimpleLogger
{
    private static readonly string logFilePath = "server_log.txt";
    private static readonly object lockObj = new object();

    public static void Log(string message)
    {
        lock (lockObj)
        {
          
            string logEntry = $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss.fff Z}] {message}";
            Console.WriteLine(logEntry);  
            File.AppendAllText(logFilePath, logEntry + Environment.NewLine);
        }
    }
}

class SecureServer
{
    public static async Task Main(string[] args)
    {
        var config = new ConfigurationBuilder()
            .AddUserSecrets<SecureServer>()
            .Build();

        string serverCertificateFile = "/Users/dmitroilcenko/Desktop/ConsoleApp3/SecureServer/bin/Debug/net9.0/server.pfx";  

        string certificatePassword = config["X509Certificate2:Password"];

        // Завантажуємо сертифікат
        X509Certificate2 serverCertificate = new X509Certificate2(serverCertificateFile, certificatePassword);
        SimpleLogger.Log("Сертифікат сервера успішно завантажено.");

        // Створюємо слухача TCP-порту 8888
        TcpListener listener = new TcpListener(IPAddress.Any, 8888);
        listener.Start();
        SimpleLogger.Log("Сервер запущено. Очікування клієнтів на порту 8888...");

        while (true)
        {
            // Чекаємо на підключення клієнта
            TcpClient client = await listener.AcceptTcpClientAsync();
            // Обробляємо кожного клієнта в окремому завданні
            _ = ProcessClientAsync(client, serverCertificate);
        }
    }

    private static async Task ProcessClientAsync(TcpClient tcpClient, X509Certificate2 certificate)
    {
        string clientEndPoint = tcpClient.Client.RemoteEndPoint.ToString();
        SimpleLogger.Log($"Клієнт під'єднався з {clientEndPoint}.");

        // Використовуємо SslStream для створення безпечного каналу
        using (SslStream sslStream = new SslStream(tcpClient.GetStream(), false))
        {
            try
            {
                // Аутентифікація сервера з використанням сертифіката
                await sslStream.AuthenticateAsServerAsync(certificate,
                    clientCertificateRequired: false,
                    SslProtocols.Tls12,
                    checkCertificateRevocation: true);
                SimpleLogger.Log($"TLS-сесію встановлено для клієнта {clientEndPoint}.");
                SimpleLogger.Log(
                    $"Протокол: {sslStream.SslProtocol}, Шифр: {sslStream.CipherAlgorithm}, Хеш: {sslStream.HashAlgorithm}");

                // Отримуємо потік для читання та запису
                using (var reader = new StreamReader(sslStream, Encoding.UTF8))
                using (var writer = new StreamWriter(sslStream, Encoding.UTF8) { AutoFlush = true })
                {
                     
                    await writer.WriteLineAsync(
                        "Ласкаво просимо! Будь ласка, надайте облікові дані у форматі 'користувач:пароль'");
                    string credentials = await reader.ReadLineAsync();

                    if (AuthenticateUser(credentials))
                    {
                        SimpleLogger.Log($"Успішна автентифікація для клієнта {clientEndPoint}.");
                        await writer.WriteLineAsync("AUTH_SUCCESS");

                        
                        await writer.WriteLineAsync("Будь ласка, надішліть ваше повідомлення.");
                        string clientMessage = await reader.ReadLineAsync();
                        SimpleLogger.Log($"Отримано повідомлення від {clientEndPoint}: '{clientMessage}'");

                        // Відправляємо відповідь
                        string serverResponse = $"Сервер отримав ваше повідомлення: '{clientMessage}' о {DateTime.Now}";
                        await writer.WriteLineAsync(serverResponse);
                        SimpleLogger.Log($"Надіслано відповідь клієнту {clientEndPoint}.");
                    }
                    else
                    {
                        SimpleLogger.Log($"Невдала спроба автентифікації від {clientEndPoint}.");
                        await writer.WriteLineAsync("AUTH_FAIL: Невірні облікові дані.");
                    }
                }
            }
            catch (AuthenticationException ex)
            {
                SimpleLogger.Log($"Автентифікація не вдалася для {clientEndPoint}: {ex.Message}");
            }
            catch (IOException ex)
            {
                SimpleLogger.Log(
                    $"Виняток вводу-виводу для {clientEndPoint}: {ex.Message}. Можливо, клієнт від'єднався.");
            }
            catch (Exception ex)
            {
                SimpleLogger.Log($"Сталася помилка з клієнтом {clientEndPoint}: {ex.Message}");
            }
            finally
            {
                tcpClient.Close();
                SimpleLogger.Log($"З'єднання з {clientEndPoint} закрито.");
            }
        }
    }

//перевірка логіна та пароля
    private static bool AuthenticateUser(string credentials)
    {
        if (string.IsNullOrEmpty(credentials)) return false;

        // Очікуваний формат: "користувач:пароль"
        string[] parts = credentials.Split(':');
        if (parts.Length != 2) return false;

        string username = parts[0];
        string password = parts[1];

        // Для прикладу, правильні дані  в коді
        return username == "myuser" && password == "mypassword123";
    }
}