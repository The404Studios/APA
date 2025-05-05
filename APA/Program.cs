using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Serialization;
using Newtonsoft.Json;
using PacketDotNet;
using ProtoBuf;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace AdvancedPacketAnalyzer
{
    // Main Application Entry Point
    class Program
    {
        private static readonly ConcurrentQueue<PacketContainer> _transportBuffer = new ConcurrentQueue<PacketContainer>();
        public static readonly List<ICaptureDevice> CaptureDevices = new List<ICaptureDevice>();
        private static readonly Dictionary<string, IProtocolHandler> _protocolHandlers = new Dictionary<string, IProtocolHandler>();
        private static readonly List<IDecryptionProvider> _decryptionProviders = new List<IDecryptionProvider>();
        private static readonly CancellationTokenSource _cancellationTokenSource = new CancellationTokenSource();
        private static readonly FileLogger _fileLogger = new FileLogger("packet_logs", LogLevel.Verbose);
        private static readonly object _consoleLock = new object();
        private static bool _verboseLogging = true;
        private static bool _isRunning = true;
        private static X509Certificate2Collection _certificateStore = new X509Certificate2Collection();
        private static byte[] _masterKey = null;
        private static Dictionary<string, SessionKeyInfo> _sessionKeys = new Dictionary<string, SessionKeyInfo>();
        public static SimpleWebServer WebServer { get; private set; }

        static async Task Main(string[] args)
        {
            Console.Title = "Advanced Packet Analyzer and Manipulator";
            DisplayBanner();

            // Initialize components
            InitializeCaptureDevices();
            RegisterProtocolHandlers();
            LoadDecryptionProviders();

            // Load certificates and keys if available
            LoadCertificatesAndKeys();

            // Start processing tasks
            var processingTasks = new List<Task>
            {
                Task.Run(() => CapturePacketsAsync(_cancellationTokenSource.Token)),
                Task.Run(() => ProcessPacketsAsync(_cancellationTokenSource.Token)),
                Task.Run(() => ForwardPacketsAsync(_cancellationTokenSource.Token)),
                Task.Run(() => HandleUserInputAsync(_cancellationTokenSource.Token))
            };

            try
            {
                LogMessage("System initialized and running. Press 'Q' to quit, 'H' for help.", LogLevel.Info);
                await Task.WhenAll(processingTasks.ToArray());
            }
            catch (Exception ex)
            {
                LogMessage($"Fatal error in main processing loop: {ex.Message}", LogLevel.Error);
                LogMessage($"Stack trace: {ex.StackTrace}", LogLevel.Debug);
            }
            finally
            {
                CleanupResources();
            }
        }

        #region Initialization Methods

        private static void DisplayBanner()
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(@"
 █████╗ ██████╗ ██╗   ██╗ █████╗ ███╗   ██╗ ██████╗███████╗██████╗     
██╔══██╗██╔══██╗██║   ██║██╔══██╗████╗  ██║██╔════╝██╔════╝██╔══██╗    
███████║██║  ██║██║   ██║███████║██╔██╗ ██║██║     █████╗  ██║  ██║    
██╔══██║██║  ██║╚██╗ ██╔╝██╔══██║██║╚██╗██║██║     ██╔══╝  ██║  ██║    
██║  ██║██████╔╝ ╚████╔╝ ██║  ██║██║ ╚████║╚██████╗███████╗██████╔╝    
╚═╝  ╚═╝╚═════╝   ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝╚═════╝     
                                                                        
██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗                      
██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝                      
██████╔╝███████║██║     █████╔╝ █████╗     ██║                         
██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║                         
██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║                         
╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝                         
                                                                        
 █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗        
██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗       
███████║██╔██╗ ██║███████║██║   ╚████╔╝   ███╔╝ █████╗  ██████╔╝       
██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗       
██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████╗███████╗██║  ██║       
╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝       
            ");
            Console.ResetColor();
            Console.WriteLine("\nAdvanced Network Packet Analyzer, Decryptor, and Manipulator v1.6.4");
            Console.WriteLine("--------------------------------------------------------\n");
            Console.WriteLine("-by-404-------http://localhost:8080 for the web UI------\n");
            Console.WriteLine("--------------------------------------------------------\n");

            // Initialize web server
            WebServer = new SimpleWebServer("http://localhost:8080/");
            WebServer.Start();
        }

        private static void InitializeCaptureDevices()
        {
            LogMessage("Initializing capture devices...", LogLevel.Info);

            try
            {
                // Get all devices
                var devices = CaptureDeviceList.Instance;

                if (devices.Count == 0)
                {
                    LogMessage("No capture devices found. Please ensure WinPcap/LibPcap is installed.", LogLevel.Error);
                    Environment.Exit(1);
                }

                // Display available devices
                Console.WriteLine("Available capture devices:");
                for (int i = 0; i < devices.Count; i++)
                {
                    var dev = devices[i];
                    Console.WriteLine($"[{i}] {dev.Description}");
                }

                // Let user select device
                Console.Write("\nSelect device number to monitor (or enter 'all' for all devices): ");
                string userInput = Console.ReadLine().Trim();

                if (userInput.ToLower() == "all")
                {
                    // Add all devices
                    foreach (var device in devices)
                    {
                        if (device is LibPcapLiveDevice liveDev)
                        {
                            ConfigureDevice(liveDev);
                            CaptureDevices.Add(liveDev);
                            LogMessage($"Added device: {liveDev.Description}", LogLevel.Info);
                        }
                    }
                }
                else if (int.TryParse(userInput, out int deviceIndex) && deviceIndex >= 0 && deviceIndex < devices.Count)
                {
                    // Add selected device
                    var selectedDevice = devices[deviceIndex] as LibPcapLiveDevice;
                    if (selectedDevice != null)
                    {
                        ConfigureDevice(selectedDevice);
                        CaptureDevices.Add(selectedDevice);
                        LogMessage($"Selected device: {selectedDevice.Description}", LogLevel.Info);
                    }
                    else
                    {
                        LogMessage("Invalid device selection. Exiting.", LogLevel.Error);
                        Environment.Exit(1);
                    }
                }
                else
                {
                    LogMessage("Invalid device selection. Exiting.", LogLevel.Error);
                    Environment.Exit(1);
                }
            }
            catch (Exception ex)
            {
                LogMessage($"Error initializing capture devices: {ex.Message}", LogLevel.Error);
                Environment.Exit(1);
            }
        }

        private static void ConfigureDevice(LibPcapLiveDevice device)
        {
            // Configure the device
            device.OnPacketArrival += DeviceOnPacketArrival;
            device.Open(DeviceModes.Promiscuous, 1000);

            // Set a filter to capture TCP and UDP packets
            device.Filter = "tcp or udp";
        }

        private static void RegisterProtocolHandlers()
        {
            LogMessage("Registering protocol handlers...", LogLevel.Info);

            // Register handlers for different protocols
            _protocolHandlers.Add("HTTP", new HttpProtocolHandler());
            _protocolHandlers.Add("HTTPS", new HttpsProtocolHandler());
            _protocolHandlers.Add("FTP", new FtpProtocolHandler());
            _protocolHandlers.Add("SMTP", new SmtpProtocolHandler());
            _protocolHandlers.Add("DNS", new DnsProtocolHandler());
            _protocolHandlers.Add("MQTT", new MqttProtocolHandler());
            _protocolHandlers.Add("SSH", new SshProtocolHandler());
            _protocolHandlers.Add("RTP", new RtpProtocolHandler());
            _protocolHandlers.Add("SIP", new SipProtocolHandler());
            _protocolHandlers.Add("RTSP", new RtspProtocolHandler());
            _protocolHandlers.Add("QUIC", new QuicProtocolHandler());
            _protocolHandlers.Add("AMQP", new AmqpProtocolHandler());
            _protocolHandlers.Add("CUSTOM", new CustomBinaryProtocolHandler());

            LogMessage($"Registered {_protocolHandlers.Count} protocol handlers", LogLevel.Info);
        }

        private static void LoadDecryptionProviders()
        {
            LogMessage("Loading decryption providers...", LogLevel.Info);

            // Register handlers for different encryption types
            _decryptionProviders.Add(new TlsDecryptionProvider());
            _decryptionProviders.Add(new SslDecryptionProvider());
            _decryptionProviders.Add(new AesDecryptionProvider());
            _decryptionProviders.Add(new ChaCha20DecryptionProvider());
            _decryptionProviders.Add(new Rc4DecryptionProvider());
            _decryptionProviders.Add(new DtlsDecryptionProvider());
            _decryptionProviders.Add(new WireGuardDecryptionProvider());
            _decryptionProviders.Add(new OpenvpnDecryptionProvider());

            LogMessage($"Loaded {_decryptionProviders.Count} decryption providers", LogLevel.Info);
        }

        private static void LoadCertificatesAndKeys()
        {
            LogMessage("Loading certificates and encryption keys...", LogLevel.Info);

            try
            {
                // Create directories if they don't exist
                string certPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "certificates");
                string keyPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "keys");

                Directory.CreateDirectory(certPath);
                Directory.CreateDirectory(keyPath);

                // Check for certificate store
                if (Directory.Exists(certPath))
                {
                    foreach (var file in Directory.GetFiles(certPath, "*.pfx"))
                    {
                        try
                        {
                            // For a real application, you'd prompt for password or use a config
                            // Default password for testing is "password"
                            var cert = new X509Certificate2(file, "password", X509KeyStorageFlags.Exportable);
                            _certificateStore.Add(cert);
                            LogMessage($"Loaded certificate: {cert.Subject}", LogLevel.Debug);
                        }
                        catch (Exception ex)
                        {
                            LogMessage($"Failed to load certificate {file}: {ex.Message}", LogLevel.Warning);
                        }
                    }
                }

                // Check for master key file (format used for TLS/SSL decryption)
                string masterKeyFile = Path.Combine(keyPath, "master.key");
                if (File.Exists(masterKeyFile))
                {
                    _masterKey = File.ReadAllBytes(masterKeyFile);
                    LogMessage("Loaded master key file", LogLevel.Info);
                }

                // Load session keys if available (similar to Wireshark SSLKEYLOGFILE)
                string sslKeyLogPath = Environment.GetEnvironmentVariable("SSLKEYLOGFILE");
                if (!string.IsNullOrEmpty(sslKeyLogPath) && File.Exists(sslKeyLogPath))
                {
                    ParseSslKeyLogFile(sslKeyLogPath);
                }
                else
                {
                    // Check for a default key log file in our application directory
                    string defaultKeyLogPath = Path.Combine(keyPath, "sslkeys.log");
                    if (File.Exists(defaultKeyLogPath))
                    {
                        ParseSslKeyLogFile(defaultKeyLogPath);
                    }
                    else
                    {
                        // Create empty SSL key log file for future use
                        File.WriteAllText(defaultKeyLogPath, "# SSL/TLS Session Key Log File - Used for decrypting TLS traffic\n");
                        LogMessage($"Created empty SSL key log file at {defaultKeyLogPath}", LogLevel.Info);
                    }
                }
            }
            catch (Exception ex)
            {
                LogMessage($"Error loading certificates and keys: {ex.Message}", LogLevel.Error);
            }
        }

        private static void ParseSslKeyLogFile(string filePath)
        {
            try
            {
                foreach (var line in File.ReadLines(filePath))
                {
                    if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                        continue;

                    string[] parts = line.Split(' ');

                    if (parts.Length >= 3)
                    {
                        string label = parts[0];
                        string clientRandom = parts[1];
                        string secretKey = parts[2];

                        SessionKeyInfo keyInfo = new SessionKeyInfo
                        {
                            Label = label,
                            ClientRandom = HexStringToByteArray(clientRandom),
                            Secret = HexStringToByteArray(secretKey)
                        };

                        _sessionKeys[clientRandom] = keyInfo;
                    }
                }

                LogMessage($"Loaded {_sessionKeys.Count} session keys from SSL key log file", LogLevel.Info);
            }
            catch (Exception ex)
            {
                LogMessage($"Error parsing SSL key log file: {ex.Message}", LogLevel.Error);
            }
        }

        private static byte[] HexStringToByteArray(string hex)
        {
            if (hex.Length % 2 == 1)
                throw new Exception("The binary key cannot have an odd number of digits");

            byte[] arr = new byte[hex.Length >> 1];

            for (int i = 0; i < hex.Length >> 1; ++i)
            {
                arr[i] = (byte)((GetHexVal(hex[i << 1]) << 4) + GetHexVal(hex[(i << 1) + 1]));
            }

            return arr;
        }

        private static int GetHexVal(char hex)
        {
            int val = (int)hex;
            return val - (val < 58 ? 48 : (val < 97 ? 55 : 87));
        }

        #endregion

        #region Packet Capture and Processing

        private static void DeviceOnPacketArrival(object sender, PacketCapture packetCapture)
        {
            try
            {
                var rawPacket = packetCapture.GetPacket();
                var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

                // Create a container for the packet data and metadata
                var packetContainer = new PacketContainer
                {
                    OriginalPacket = packet,
                    RawData = rawPacket.Data,
                    CaptureTime = rawPacket.Timeval.Date,
                    InterfaceName = ((ICaptureDevice)sender).Name,
                    PacketLength = rawPacket.Data.Length,
                    PacketStatus = PacketStatus.Captured
                };

                // Extract basic protocol information
                ExtractPacketInfo(packetContainer);

                // Add to transport buffer for processing
                _transportBuffer.Enqueue(packetContainer);

                // Also send to web interface
                WebServer.EnqueuePacket(packetContainer);
            }
            catch (Exception ex)
            {
                LogMessage($"Error processing captured packet: {ex.Message}", LogLevel.Error);
            }
        }

        private static void ExtractPacketInfo(PacketContainer container)
        {
            try
            {
                var packet = container.OriginalPacket;

                // TCP packet
                var tcpPacket = packet.Extract<TcpPacket>();
                if (tcpPacket != null)
                {
                    // Check if parent packet is IPv4 or IPv6
                    var ipv4Packet = tcpPacket.ParentPacket as IPv4Packet;
                    var ipv6Packet = tcpPacket.ParentPacket as IPv6Packet;

                    if (ipv4Packet != null)
                    {
                        container.SourceIp = ipv4Packet.SourceAddress.ToString();
                        container.DestinationIp = ipv4Packet.DestinationAddress.ToString();
                    }
                    else if (ipv6Packet != null)
                    {
                        container.SourceIp = ipv6Packet.SourceAddress.ToString();
                        container.DestinationIp = ipv6Packet.DestinationAddress.ToString();
                    }

                    container.SourcePort = tcpPacket.SourcePort;
                    container.DestinationPort = tcpPacket.DestinationPort;
                    container.TransportProtocol = "TCP";
                    container.SequenceNumber = tcpPacket.SequenceNumber;
                    container.AcknowledgmentNumber = tcpPacket.AcknowledgmentNumber;
                    container.PayloadData = tcpPacket.PayloadData;

                    // Detect application protocol based on port
                    DetectApplicationProtocol(container);
                    return;
                }

                // UDP packet
                var udpPacket = packet.Extract<UdpPacket>();
                if (udpPacket != null)
                {
                    // Check if parent packet is IPv4 or IPv6
                    var ipv4Packet = udpPacket.ParentPacket as IPv4Packet;
                    var ipv6Packet = udpPacket.ParentPacket as IPv6Packet;

                    if (ipv4Packet != null)
                    {
                        container.SourceIp = ipv4Packet.SourceAddress.ToString();
                        container.DestinationIp = ipv4Packet.DestinationAddress.ToString();
                    }
                    else if (ipv6Packet != null)
                    {
                        container.SourceIp = ipv6Packet.SourceAddress.ToString();
                        container.DestinationIp = ipv6Packet.DestinationAddress.ToString();
                    }

                    container.SourcePort = udpPacket.SourcePort;
                    container.DestinationPort = udpPacket.DestinationPort;
                    container.TransportProtocol = "UDP";
                    container.PayloadData = udpPacket.PayloadData;

                    // Detect application protocol based on port
                    DetectApplicationProtocol(container);
                    return;
                }
            }
            catch (Exception ex)
            {
                LogMessage($"Error extracting packet info: {ex.Message}", LogLevel.Error);
            }
        }

        private static void DetectApplicationProtocol(PacketContainer container)
        {
            try
            {
                // First try basic detection with common ports
                // Check for common ports
                switch (container.DestinationPort)
                {
                    case 80:
                        container.ApplicationProtocol = "HTTP";
                        break;
                    case 443:
                        container.ApplicationProtocol = "HTTPS";
                        container.IsEncrypted = true;
                        break;
                    case 21:
                    case 20:
                        container.ApplicationProtocol = "FTP";
                        break;
                    case 22:
                        container.ApplicationProtocol = "SSH";
                        container.IsEncrypted = true;
                        break;
                    case 25:
                    case 587:
                    case 465:
                        container.ApplicationProtocol = "SMTP";
                        if (container.DestinationPort == 465)
                            container.IsEncrypted = true;
                        break;
                    case 53:
                        container.ApplicationProtocol = "DNS";
                        break;
                    case 110:
                    case 995:
                        container.ApplicationProtocol = "POP3";
                        if (container.DestinationPort == 995)
                            container.IsEncrypted = true;
                        break;
                    case 143:
                    case 993:
                        container.ApplicationProtocol = "IMAP";
                        if (container.DestinationPort == 993)
                            container.IsEncrypted = true;
                        break;
                    case 1883:
                    case 8883:
                        container.ApplicationProtocol = "MQTT";
                        if (container.DestinationPort == 8883)
                            container.IsEncrypted = true;
                        break;
                    case 5060:
                    case 5061:
                        container.ApplicationProtocol = "SIP";
                        if (container.DestinationPort == 5061)
                            container.IsEncrypted = true;
                        break;
                    case 554:
                        container.ApplicationProtocol = "RTSP";
                        break;
                    case 3389:
                        container.ApplicationProtocol = "RDP";
                        container.IsEncrypted = true;
                        break;
                    case 5222:
                    case 5223:
                        container.ApplicationProtocol = "XMPP";
                        if (container.DestinationPort == 5223)
                            container.IsEncrypted = true;
                        break;
                    case 5672:
                    case 5671:
                        container.ApplicationProtocol = "AMQP";
                        if (container.DestinationPort == 5671)
                            container.IsEncrypted = true;
                        break;
                    default:
                        // For non-standard ports, use advanced detection
                        container.ApplicationProtocol = "UNKNOWN";
                        break;
                }

                // Also check source port for server responses
                if (string.IsNullOrEmpty(container.ApplicationProtocol) || container.ApplicationProtocol == "UNKNOWN")
                {
                    switch (container.SourcePort)
                    {
                        case 80:
                            container.ApplicationProtocol = "HTTP";
                            break;
                        case 443:
                            container.ApplicationProtocol = "HTTPS";
                            container.IsEncrypted = true;
                            break;
                        case 53:
                            container.ApplicationProtocol = "DNS";
                            break;
                            // Add other protocols as needed
                    }
                }

                // If we have payload data, use the advanced protocol identifier
                if (container.PayloadData != null && container.PayloadData.Length > 0 &&
                    (string.IsNullOrEmpty(container.ApplicationProtocol) ||
                     container.ApplicationProtocol == "UNKNOWN" ||
                     container.ApplicationProtocol == "BINARY"))
                {
                    // Use our advanced protocol detection
                    container.IdentifyProtocol();
                }

                // If we still don't have a protocol and have payload data, use the simple detection
                if ((string.IsNullOrEmpty(container.ApplicationProtocol) ||
                    container.ApplicationProtocol == "UNKNOWN") &&
                    container.PayloadData != null && container.PayloadData.Length > 0)
                {
                    // Fall back to simple payload-based detection
                    DetectProtocolFromPayload(container);
                }
            }
            catch (Exception ex)
            {
                LogMessage($"Error detecting application protocol: {ex.Message}", LogLevel.Error);
            }
        }

        private static void DetectProtocolFromPayload(PacketContainer container)
        {
            // If we have no payload, we can't detect
            if (container.PayloadData == null || container.PayloadData.Length == 0)
            {
                container.ApplicationProtocol = "UNKNOWN";
                return;
            }

            try
            {
                // Convert first bytes to string for text-based protocol detection
                // Be more careful with encoding - only use ASCII for the first few bytes
                string payloadStart = "";
                try
                {
                    payloadStart = Encoding.ASCII.GetString(
                        container.PayloadData,
                        0,
                        Math.Min(container.PayloadData.Length, 10)
                    );
                }
                catch
                {
                    // If we can't convert to ASCII, it's likely binary
                    payloadStart = "";
                }

                // Check for common protocol signatures
                if (payloadStart.StartsWith("GET ") ||
                    payloadStart.StartsWith("POST ") ||
                    payloadStart.StartsWith("HTTP/"))
                {
                    container.ApplicationProtocol = "HTTP";
                }
                else if (payloadStart.StartsWith("MQTT"))
                {
                    container.ApplicationProtocol = "MQTT";
                }
                else if (payloadStart.StartsWith("SSH-"))
                {
                    container.ApplicationProtocol = "SSH";
                    container.IsEncrypted = true;
                }
                else if (payloadStart.StartsWith("RTSP/"))
                {
                    container.ApplicationProtocol = "RTSP";
                }
                else if (payloadStart.StartsWith("SIP/"))
                {
                    container.ApplicationProtocol = "SIP";
                }
                else if (container.PayloadData.Length >= 2)
                {
                    // Check for binary protocol signatures
                    if (container.PayloadData[0] == 0x16 && (container.PayloadData[1] == 0x03 || container.PayloadData[1] == 0x02 || container.PayloadData[1] == 0x01))
                    {
                        // Likely TLS handshake (TLS 1.0, 1.1, 1.2, 1.3)
                        container.ApplicationProtocol = "TLS";
                        container.IsEncrypted = true;
                    }
                    else if (container.PayloadData[0] == 0x17 && (container.PayloadData[1] == 0x03 || container.PayloadData[1] == 0x02 || container.PayloadData[1] == 0x01))
                    {
                        // Likely TLS application data
                        container.ApplicationProtocol = "TLS";
                        container.IsEncrypted = true;
                    }
                    else
                    {
                        // Try deeper protocol analysis for binary protocols
                        DetectBinaryProtocol(container);
                    }
                }
                else
                {
                    container.ApplicationProtocol = "UNKNOWN";
                }
            }
            catch (Exception ex)
            {
                LogMessage($"Error during payload-based protocol detection: {ex.Message}", LogLevel.Error);
                container.ApplicationProtocol = "UNKNOWN";
            }
        }

        private static void DetectBinaryProtocol(PacketContainer container)
        {
            // More comprehensive binary protocol detection
            // This would normally contain complex pattern matching logic

            try
            {
                // Example: DNS packet (basic detection)
                if (container.TransportProtocol == "UDP" && container.PayloadData.Length > 4)
                {
                    // DNS typically has a 12-byte header
                    // Simple heuristic: Check for common question types/classes in DNS
                    if (container.PayloadData.Length >= 12 &&
                        (container.SourcePort == 53 || container.DestinationPort == 53))
                    {
                        container.ApplicationProtocol = "DNS";
                        return;
                    }
                }

                // Example: Detect WebSocket traffic
                if (container.TransportProtocol == "TCP" && container.PayloadData.Length > 2)
                {
                    // WebSocket frames start with a byte where:
                    // - Bit 0 is FIN
                    // - Bits 1-3 are reserved
                    // - Bits 4-7 are opcode
                    byte firstByte = container.PayloadData[0];
                    byte secondByte = container.PayloadData[1];

                    // Check if it looks like a WebSocket frame
                    // This is a very simplified check and would need more validation
                    if ((firstByte & 0x70) == 0 && // Reserved bits must be 0
                        (firstByte & 0x0F) <= 0x0A && // Valid opcode range
                        (secondByte & 0x80) != 0) // Mask bit should be set for client->server
                    {
                        container.ApplicationProtocol = "WebSocket";
                        return;
                    }
                }

                // Add more protocol detection logic as needed

                // Default to BINARY if no specific protocol detected
                container.ApplicationProtocol = "BINARY";
            }
            catch (Exception ex)
            {
                LogMessage($"Error in binary protocol detection: {ex.Message}", LogLevel.Error);
                container.ApplicationProtocol = "UNKNOWN";
            }
        }

        private static async Task CapturePacketsAsync(CancellationToken cancellationToken)
        {
            try
            {
                LogMessage("Starting packet capture...", LogLevel.Info);

                foreach (var device in CaptureDevices)
                {
                    if (!device.Started)
                    {
                        device.StartCapture();
                        LogMessage($"Started capture on {device.Description}", LogLevel.Info);
                    }
                }

                // Keep task alive while capture is running
                while (!cancellationToken.IsCancellationRequested && _isRunning)
                {
                    await Task.Delay(1000, cancellationToken);
                }
            }
            catch (OperationCanceledException)
            {
                // Expected when token is canceled
            }
            catch (Exception ex)
            {
                LogMessage($"Error in packet capture task: {ex.Message}", LogLevel.Error);
            }
            finally
            {
                foreach (var device in CaptureDevices)
                {
                    try
                    {
                        if (device.Started)
                        {
                            device.StopCapture();
                            LogMessage($"Stopped capture on {device.Description}", LogLevel.Info);
                        }
                    }
                    catch (Exception ex)
                    {
                        LogMessage($"Error stopping device capture: {ex.Message}", LogLevel.Error);
                    }
                }
            }
        }

        private static async Task ProcessPacketsAsync(CancellationToken cancellationToken)
        {
            LogMessage("Starting packet processing...", LogLevel.Info);

            try
            {
                while (!cancellationToken.IsCancellationRequested && _isRunning)
                {
                    // Process up to 10 packets per cycle
                    int processedCount = 0;
                    while (processedCount < 10 && _transportBuffer.TryDequeue(out var packetContainer))
                    {
                        try
                        {
                            await ProcessSinglePacketAsync(packetContainer);
                            processedCount++;
                        }
                        catch (Exception ex)
                        {
                            LogMessage($"Error processing packet: {ex.Message}", LogLevel.Error);
                        }
                    }

                    // Small delay to prevent CPU thrashing if queue is empty
                    if (processedCount == 0)
                    {
                        await Task.Delay(10, cancellationToken);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Expected when token is canceled
            }
            catch (Exception ex)
            {
                LogMessage($"Error in packet processing task: {ex.Message}", LogLevel.Error);
            }
        }

        private static async Task ProcessSinglePacketAsync(PacketContainer packet)
        {
            // Update status
            packet.PacketStatus = PacketStatus.Processing;

            // Log basic packet info
            LogPacketInfo(packet);

            try
            {
                // 1. Try to decrypt if encrypted
                if (packet.IsEncrypted)
                {
                    await DecryptPacketAsync(packet);
                }

                // 2. Deserialize if we have a protocol handler
                if (!string.IsNullOrEmpty(packet.ApplicationProtocol) &&
                    _protocolHandlers.TryGetValue(packet.ApplicationProtocol, out var handler))
                {
                    await DeserializePacketAsync(packet, handler);
                }

                // 3. Log the packet details to file
                await LogPacketToFileAsync(packet);

                // 4. Reserialize if needed for forwarding
                if (packet.ShouldForward && packet.DeserializedData != null)
                {
                    await ReserializePacketAsync(packet);
                }

                // Update status
                packet.PacketStatus = packet.HasErrors ? PacketStatus.Error : PacketStatus.Processed;
            }
            catch (Exception ex)
            {
                packet.ErrorMessages.Add($"Processing error: {ex.Message}");
                packet.PacketStatus = PacketStatus.Error;
                LogMessage($"Error processing packet: {ex.Message}", LogLevel.Error);
            }
        }

        private static async Task DecryptPacketAsync(PacketContainer packet)
        {
            LogMessage($"Attempting to decrypt {packet.ApplicationProtocol} packet...", LogLevel.Debug);

            try
            {
                bool decrypted = false;

                // Try each decryption provider
                foreach (var provider in _decryptionProviders)
                {
                    if (await provider.CanDecryptAsync(packet))
                    {
                        decrypted = await provider.DecryptAsync(packet, _certificateStore, _masterKey, _sessionKeys);
                        if (decrypted)
                        {
                            LogMessage($"Packet decrypted successfully using {provider.GetType().Name}", LogLevel.Debug);
                            break;
                        }
                    }
                }

                if (!decrypted)
                {
                    LogMessage("Unable to decrypt packet, missing keys or unsupported encryption", LogLevel.Warning);
                    packet.ErrorMessages.Add("Decryption failed: missing keys or unsupported encryption");
                }
            }
            catch (Exception ex)
            {
                LogMessage($"Error during packet decryption: {ex.Message}", LogLevel.Error);
                packet.ErrorMessages.Add($"Decryption error: {ex.Message}");
            }
        }

        private static async Task DeserializePacketAsync(PacketContainer packet, IProtocolHandler handler)
        {
            LogMessage($"Deserializing {packet.ApplicationProtocol} packet...", LogLevel.Debug);

            try
            {
                bool deserialized = await handler.DeserializeAsync(packet);

                if (deserialized)
                {
                    LogMessage("Packet deserialized successfully", LogLevel.Debug);
                }
                else
                {
                    LogMessage("Packet deserialization failed", LogLevel.Warning);
                    packet.ErrorMessages.Add("Deserialization failed: unsupported format or corrupt data");
                }
            }
            catch (Exception ex)
            {
                LogMessage($"Error during packet deserialization: {ex.Message}", LogLevel.Error);
                packet.ErrorMessages.Add($"Deserialization error: {ex.Message}");
            }
        }

        private static async Task LogPacketToFileAsync(PacketContainer packet)
        {
            try
            {
                // Prepare log entry
                var logEntry = new PacketLogEntry
                {
                    Timestamp = packet.CaptureTime,
                    SourceIp = packet.SourceIp,
                    DestinationIp = packet.DestinationIp,
                    SourcePort = packet.SourcePort,
                    DestinationPort = packet.DestinationPort,
                    TransportProtocol = packet.TransportProtocol,
                    ApplicationProtocol = packet.ApplicationProtocol,
                    PacketLength = packet.PacketLength,
                    IsEncrypted = packet.IsEncrypted,
                    WasDecrypted = packet.WasDecrypted,
                    ErrorMessages = string.Join("; ", packet.ErrorMessages),
                    SerializedPayload = packet.DeserializedData != null
                        ? JsonConvert.SerializeObject(packet.DeserializedData)
                        : "No deserialized data available"
                };

                // Log to file
                await _fileLogger.LogPacketAsync(logEntry);
            }
            catch (Exception ex)
            {
                LogMessage($"Error logging packet to file: {ex.Message}", LogLevel.Error);
            }
        }

        private static async Task ReserializePacketAsync(PacketContainer packet)
        {
            if (packet.DeserializedData == null)
                return;

            LogMessage($"Reserializing {packet.ApplicationProtocol} packet for forwarding...", LogLevel.Debug);

            try
            {
                if (!string.IsNullOrEmpty(packet.ApplicationProtocol) &&
                    _protocolHandlers.TryGetValue(packet.ApplicationProtocol, out var handler))
                {
                    bool reserialized = await handler.SerializeAsync(packet);

                    if (reserialized)
                    {
                        LogMessage("Packet reserialized successfully", LogLevel.Debug);
                    }
                    else
                    {
                        LogMessage("Packet reserialization failed", LogLevel.Warning);
                        packet.ErrorMessages.Add("Reserialization failed");
                        packet.ShouldForward = false;
                    }
                }
                else
                {
                    // Cannot reserialize without a protocol handler
                    packet.ShouldForward = false;
                }
            }
            catch (Exception ex)
            {
                LogMessage($"Error during packet reserialization: {ex.Message}", LogLevel.Error);
                packet.ErrorMessages.Add($"Reserialization error: {ex.Message}");
                packet.ShouldForward = false;
            }
        }

        private static async Task ForwardPacketsAsync(CancellationToken cancellationToken)
        {
            LogMessage("Starting packet forwarding...", LogLevel.Info);

            // Create a queue for packets that need forwarding
            var forwardingQueue = new ConcurrentQueue<PacketContainer>();

            try
            {
                while (!cancellationToken.IsCancellationRequested && _isRunning)
                {
                    // Wait a bit to avoid thrashing CPU
                    await Task.Delay(50, cancellationToken);

                    // Process forwarding queue
                    int forwardedCount = 0;
                    while (forwardedCount < 10 && forwardingQueue.TryDequeue(out var packet))
                    {
                        try
                        {
                            await ForwardSinglePacketAsync(packet);
                            forwardedCount++;
                        }
                        catch (Exception ex)
                        {
                            LogMessage($"Error forwarding packet: {ex.Message}", LogLevel.Error);
                        }
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Expected when token is canceled
            }
            catch (Exception ex)
            {
                LogMessage($"Error in packet forwarding task: {ex.Message}", LogLevel.Error);
            }
        }

        private static async Task ForwardSinglePacketAsync(PacketContainer packet)
        {
            if (!packet.ShouldForward || packet.ReserializedData == null)
                return;

            LogMessage($"Forwarding packet to {packet.DestinationIp}:{packet.DestinationPort}...", LogLevel.Debug);

            try
            {
                // In a real implementation, this would actually forward the packet
                // For this demo, we'll just simulate forwarding

                // Simulate network activity
                await Task.Delay(5);

                LogMessage("Packet forwarded successfully", LogLevel.Debug);
                packet.PacketStatus = PacketStatus.Forwarded;
            }
            catch (Exception ex)
            {
                LogMessage($"Error forwarding packet: {ex.Message}", LogLevel.Error);
                packet.ErrorMessages.Add($"Forwarding error: {ex.Message}");
            }
        }

        #endregion

        #region User Interface and Logging

        private static async Task HandleUserInputAsync(CancellationToken cancellationToken)
        {
            try
            {
                while (!cancellationToken.IsCancellationRequested && _isRunning)
                {
                    if (Console.KeyAvailable)
                    {
                        var key = Console.ReadKey(true);

                        switch (char.ToUpper(key.KeyChar))
                        {
                            case 'Q':
                                LogMessage("Shutting down...", LogLevel.Info);
                                _isRunning = false;
                                _cancellationTokenSource.Cancel();
                                break;

                            case 'H':
                                DisplayHelpMenu();
                                break;

                            case 'S':
                                DisplayStatistics();
                                break;

                            case 'V':
                                _verboseLogging = !_verboseLogging;
                                LogMessage($"Verbose logging {(_verboseLogging ? "enabled" : "disabled")}", LogLevel.Info);
                                break;

                            case 'C':
                                Console.Clear();
                                DisplayBanner();
                                break;

                            case 'F':
                                // Toggle packet forwarding
                                // In a real implementation, this would enable/disable packet forwarding
                                LogMessage("Packet forwarding toggled", LogLevel.Info);
                                break;

                            case 'D':
                                // Display detected devices
                                DisplayCaptureDevices();
                                break;
                        }
                    }

                    await Task.Delay(100, cancellationToken);
                }
            }
            catch (OperationCanceledException)
            {
                // Expected when token is canceled
            }
            catch (Exception ex)
            {
                LogMessage($"Error in user input handler: {ex.Message}", LogLevel.Error);
            }
        }

        private static void DisplayHelpMenu()
        {
            Console.WriteLine("\n=== Command Help ===");
            Console.WriteLine("Q - Quit the application");
            Console.WriteLine("H - Display this help menu");
            Console.WriteLine("S - Show statistics");
            Console.WriteLine("V - Toggle verbose logging");
            Console.WriteLine("C - Clear console");
            Console.WriteLine("F - Toggle packet forwarding");
            Console.WriteLine("D - Display capture devices");
            Console.WriteLine("==================\n");
        }

        private static void DisplayCaptureDevices()
        {
            Console.WriteLine("\n=== Capture Devices ===");

            if (CaptureDevices.Count == 0)
            {
                Console.WriteLine("No capture devices available.");
            }
            else
            {
                for (int i = 0; i < CaptureDevices.Count; i++)
                {
                    var device = CaptureDevices[i];
                    Console.WriteLine($"[{i}] {device.Description}");
                    Console.WriteLine($"    Status: {(device.Started ? "Running" : "Stopped")}");

                    if (device is LibPcapLiveDevice liveDev)
                    {
                        Console.WriteLine($"    Interface: {liveDev.Interface.FriendlyName ?? liveDev.Interface.Name}");
                        Console.WriteLine($"    MAC: {liveDev.Interface.MacAddress}");
                    }
                }
            }

            Console.WriteLine("======================\n");
        }

        private static void DisplayStatistics()
        {
            // This would display statistics about captured and processed packets
            Console.WriteLine("\n=== Statistics ===");

            int capturedCount = 0;
            int processedCount = 0;
            int decryptedCount = 0;
            int forwardedCount = 0;
            int errorCount = 0;

            Console.WriteLine($"Captured packets: {capturedCount}");
            Console.WriteLine($"Processed packets: {processedCount}");
            Console.WriteLine($"Decrypted packets: {decryptedCount}");
            Console.WriteLine($"Forwarded packets: {forwardedCount}");
            Console.WriteLine($"Errors encountered: {errorCount}");
            Console.WriteLine("================\n");
        }

        private static void LogMessage(string message, LogLevel level)
        {
            // Skip debug messages if verbose logging is disabled
            if (!_verboseLogging && level == LogLevel.Debug)
                return;

            lock (_consoleLock)
            {
                // Set color based on log level
                Console.ForegroundColor = level switch
                {
                    LogLevel.Debug => ConsoleColor.Gray,
                    LogLevel.Info => ConsoleColor.White,
                    LogLevel.Warning => ConsoleColor.Yellow,
                    LogLevel.Error => ConsoleColor.Red,
                    LogLevel.Verbose => ConsoleColor.DarkGray,
                    _ => ConsoleColor.White
                };

                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [{level}] {message}");
                Console.ResetColor();

                // Also log to file if needed
                _fileLogger.LogMessage(message, level);
            }
        }

        private static void LogPacketInfo(PacketContainer packet)
        {
            if (!_verboseLogging)
                return;

            lock (_consoleLock)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] Packet: {packet.TransportProtocol}/{packet.ApplicationProtocol} " +
                                  $"{packet.SourceIp}:{packet.SourcePort} -> {packet.DestinationIp}:{packet.DestinationPort} " +
                                  $"({packet.PacketLength} bytes){(packet.IsEncrypted ? " Encrypted" : "")}");
                Console.ResetColor();
            }
        }

        #endregion

        #region Cleanup

        private static void CleanupResources()
        {
            LogMessage("Cleaning up resources...", LogLevel.Info);

            // Stop web server
            if (WebServer != null)
            {
                try
                {
                    WebServer.Stop();
                    LogMessage("Web server stopped", LogLevel.Info);
                }
                catch (Exception ex)
                {
                    LogMessage($"Error stopping web server: {ex.Message}", LogLevel.Error);
                }
            }

            // Close devices
            foreach (var device in CaptureDevices)
            {
                try
                {
                    if (device.Started)
                    {
                        device.StopCapture();
                    }
                    device.Close();
                }
                catch (Exception ex)
                {
                    LogMessage($"Error closing device: {ex.Message}", LogLevel.Error);
                }
            }

            // Close logger
            _fileLogger.Close();

            LogMessage("Cleanup complete", LogLevel.Info);
        }

        #endregion
    }

    #region Data Structures and Interfaces

    /// <summary>
    /// Container for packet data and metadata
    /// </summary>
    public class PacketContainer
    {
        // Original packet data
        public Packet OriginalPacket { get; set; }
        public byte[] RawData { get; set; }
        public DateTime CaptureTime { get; set; }
        public string InterfaceName { get; set; }
        public int PacketLength { get; set; }

        // Network information
        public string SourceIp { get; set; }
        public string DestinationIp { get; set; }
        public ushort SourcePort { get; set; }
        public ushort DestinationPort { get; set; }
        public string TransportProtocol { get; set; }
        public string ApplicationProtocol { get; set; }
        public uint SequenceNumber { get; set; }
        public uint AcknowledgmentNumber { get; set; }

        // Payload data
        public byte[] PayloadData { get; set; }
        public bool IsEncrypted { get; set; }
        public bool WasDecrypted { get; set; }

        // Processing state
        public PacketStatus PacketStatus { get; set; } = PacketStatus.New;
        public List<string> ErrorMessages { get; set; } = new List<string>();
        public bool HasErrors => ErrorMessages.Count > 0;

        // Deserialized data
        public object DeserializedData { get; set; }
        public Type DeserializedType { get; set; }

        // Forwarding
        public bool ShouldForward { get; set; } = false;
        public byte[] ReserializedData { get; set; }

        // Decryption data
        public byte[] DecryptionKey { get; set; }
        public byte[] InitializationVector { get; set; }

        // Additional metadata and detection information
        public Dictionary<string, string> AdditionalInfo { get; set; }
    }

    /// <summary>
    /// Entry for packet logging
    /// </summary>
    public class PacketLogEntry
    {
        public DateTime Timestamp { get; set; }
        public string SourceIp { get; set; }
        public string DestinationIp { get; set; }
        public ushort SourcePort { get; set; }
        public ushort DestinationPort { get; set; }
        public string TransportProtocol { get; set; }
        public string ApplicationProtocol { get; set; }
        public int PacketLength { get; set; }
        public bool IsEncrypted { get; set; }
        public bool WasDecrypted { get; set; }
        public string ErrorMessages { get; set; }
        public string SerializedPayload { get; set; }
    }

    /// <summary>
    /// Session key information for TLS/SSL decryption
    /// </summary>
    public class SessionKeyInfo
    {
        public string Label { get; set; }
        public byte[] ClientRandom { get; set; }
        public byte[] Secret { get; set; }
    }

    /// <summary>
    /// Protocol handler interface
    /// </summary>
    public interface IProtocolHandler
    {
        Task<bool> DeserializeAsync(PacketContainer packet);
        Task<bool> SerializeAsync(PacketContainer packet);
    }

    /// <summary>
    /// Decryption provider interface
    /// </summary>
    public interface IDecryptionProvider
    {
        Task<bool> CanDecryptAsync(PacketContainer packet);
        Task<bool> DecryptAsync(PacketContainer packet, X509Certificate2Collection certificates, byte[] masterKey, Dictionary<string, SessionKeyInfo> sessionKeys);
    }

    /// <summary>
    /// File logger for packet data
    /// </summary>
    public class FileLogger
    {
        private readonly string _baseDirectory;
        private readonly LogLevel _logLevel;
        private string _currentLogFile;
        private string _currentPacketLogFile;
        private static readonly object _fileLock = new object();

        public FileLogger(string directory, LogLevel minimumLevel)
        {
            _baseDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, directory);
            _logLevel = minimumLevel;

            // Create directory if it doesn't exist
            if (!Directory.Exists(_baseDirectory))
            {
                Directory.CreateDirectory(_baseDirectory);
            }

            // Create subdirectories
            Directory.CreateDirectory(Path.Combine(_baseDirectory, "system"));
            Directory.CreateDirectory(Path.Combine(_baseDirectory, "packets"));

            // Initialize log files
            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            _currentLogFile = Path.Combine(_baseDirectory, "system", $"system_log_{timestamp}.txt");
            _currentPacketLogFile = Path.Combine(_baseDirectory, "packets", $"packet_log_{timestamp}.json");

            // Create log files with headers
            File.WriteAllText(_currentLogFile, $"=== System Log Started at {DateTime.Now} ===\n\n");
            File.WriteAllText(_currentPacketLogFile, "[\n"); // Start JSON array
        }

        public void LogMessage(string message, LogLevel level)
        {
            if (level < _logLevel)
                return;

            try
            {
                lock (_fileLock)
                {
                    File.AppendAllText(_currentLogFile, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] [{level}] {message}\n");
                }
            }
            catch (Exception ex)
            {
                // Can't do much if logging fails
                Console.WriteLine($"Error writing to log file: {ex.Message}");
            }
        }

        public async Task LogPacketAsync(PacketLogEntry entry)
        {
            try
            {
                string json = JsonConvert.SerializeObject(entry, Formatting.Indented);

                // Use a semaphore-like approach instead of lock with await
                await Task.Run(() => {
                    lock (_fileLock)
                    {
                        // Get the current file size
                        FileInfo fileInfo = new FileInfo(_currentPacketLogFile);
                        long fileSize = fileInfo.Length;

                        using (FileStream fs = new FileStream(_currentPacketLogFile, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                        {
                            // Check if this is the first entry
                            if (fileSize <= 2) // Only contains "[\n"
                            {
                                fs.Seek(fileSize, SeekOrigin.Begin);
                                using (StreamWriter writer = new StreamWriter(fs))
                                {
                                    writer.Write(json + "\n");
                                    writer.Flush();
                                }
                            }
                            else
                            {
                                // Not the first entry, need to add a comma after the previous entry
                                fs.Seek(fileSize - 1, SeekOrigin.Begin);
                                using (StreamWriter writer = new StreamWriter(fs))
                                {
                                    writer.Write(",\n" + json + "\n");
                                    writer.Flush();
                                }
                            }
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error logging packet to file: {ex.Message}");
            }
        }

        public void Close()
        {
            try
            {
                lock (_fileLock)
                {
                    // Properly close the JSON array in the packet log file
                    File.AppendAllText(_currentPacketLogFile, "]\n");

                    // Add a closing message to the system log
                    File.AppendAllText(_currentLogFile, $"\n=== System Log Closed at {DateTime.Now} ===\n");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error closing log files: {ex.Message}");
            }
        }
    }

    /// <summary>
    /// Packet processing status
    /// </summary>
    public enum PacketStatus
    {
        New,
        Captured,
        Processing,
        Processed,
        Forwarded,
        Error
    }

    /// <summary>
    /// Log levels
    /// </summary>
    public enum LogLevel
    {
        Verbose = 0,
        Debug = 1,
        Info = 2,
        Warning = 3,
        Error = 4
    }

    #endregion

    #region Protocol Handlers

    // Base implementation for protocol handlers
    public abstract class BaseProtocolHandler : IProtocolHandler
    {
        public abstract Task<bool> DeserializeAsync(PacketContainer packet);
        public abstract Task<bool> SerializeAsync(PacketContainer packet);

        protected byte[] GetPayloadData(PacketContainer packet)
        {
            return packet.WasDecrypted ? packet.PayloadData : packet.PayloadData;
        }
    }

    // HTTP Protocol Handler
    public class HttpProtocolHandler : BaseProtocolHandler
    {
        public override async Task<bool> DeserializeAsync(PacketContainer packet)
        {
            try
            {
                byte[] data = GetPayloadData(packet);
                if (data == null || data.Length == 0)
                    return false;

                string httpContent = Encoding.ASCII.GetString(data);

                // Very simple HTTP parser - in a real app you would use a proper parser
                var httpObject = new HttpMessage();

                // Check if request or response
                if (httpContent.StartsWith("HTTP/"))
                {
                    // It's a response
                    httpObject.IsRequest = false;

                    // Parse first line
                    int endOfFirstLine = httpContent.IndexOf("\r\n");
                    if (endOfFirstLine > 0)
                    {
                        string firstLine = httpContent.Substring(0, endOfFirstLine);
                        string[] parts = firstLine.Split(' ');

                        if (parts.Length >= 2)
                        {
                            httpObject.HttpVersion = parts[0];
                            httpObject.StatusCode = int.Parse(parts[1]);
                        }
                    }
                }
                else
                {
                    // It's a request
                    httpObject.IsRequest = true;

                    // Parse first line
                    int endOfFirstLine = httpContent.IndexOf("\r\n");
                    if (endOfFirstLine > 0)
                    {
                        string firstLine = httpContent.Substring(0, endOfFirstLine);
                        string[] parts = firstLine.Split(' ');

                        if (parts.Length >= 3)
                        {
                            httpObject.Method = parts[0];
                            httpObject.Path = parts[1];
                            httpObject.HttpVersion = parts[2];
                        }
                    }
                }

                // Parse headers
                int headersStart = httpContent.IndexOf("\r\n") + 2;
                int headersEnd = httpContent.IndexOf("\r\n\r\n");

                if (headersStart > 0 && headersEnd > 0)
                {
                    string headersSection = httpContent.Substring(headersStart, headersEnd - headersStart);
                    string[] headerLines = headersSection.Split(new[] { "\r\n" }, StringSplitOptions.None);

                    foreach (var headerLine in headerLines)
                    {
                        int colonPos = headerLine.IndexOf(':');
                        if (colonPos > 0)
                        {
                            string name = headerLine.Substring(0, colonPos).Trim();
                            string value = headerLine.Substring(colonPos + 1).Trim();
                            httpObject.Headers[name] = value;
                        }
                    }
                }

                // Parse body
                if (headersEnd > 0)
                {
                    httpObject.Body = httpContent.Substring(headersEnd + 4);
                }

                packet.DeserializedData = httpObject;
                packet.DeserializedType = typeof(HttpMessage);

                return true;
            }
            catch (Exception ex)
            {
                packet.ErrorMessages.Add($"HTTP deserialization error: {ex.Message}");
                return false;
            }
        }

        public override async Task<bool> SerializeAsync(PacketContainer packet)
        {
            try
            {
                if (packet.DeserializedData is HttpMessage httpMessage)
                {
                    var sb = new StringBuilder();

                    // Build first line
                    if (httpMessage.IsRequest)
                    {
                        sb.AppendLine($"{httpMessage.Method} {httpMessage.Path} {httpMessage.HttpVersion}");
                    }
                    else
                    {
                        sb.AppendLine($"{httpMessage.HttpVersion} {httpMessage.StatusCode} {GetStatusText(httpMessage.StatusCode)}");
                    }

                    // Add headers
                    foreach (var header in httpMessage.Headers)
                    {
                        sb.AppendLine($"{header.Key}: {header.Value}");
                    }

                    // Add blank line and body
                    sb.AppendLine();
                    sb.Append(httpMessage.Body);

                    packet.ReserializedData = Encoding.ASCII.GetBytes(sb.ToString());
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                packet.ErrorMessages.Add($"HTTP serialization error: {ex.Message}");
                return false;
            }
        }

        private string GetStatusText(int statusCode)
        {
            return statusCode switch
            {
                200 => "OK",
                201 => "Created",
                204 => "No Content",
                301 => "Moved Permanently",
                302 => "Found",
                400 => "Bad Request",
                401 => "Unauthorized",
                403 => "Forbidden",
                404 => "Not Found",
                500 => "Internal Server Error",
                _ => "Unknown"
            };
        }
    }

    // Simple HTTPS handler that extends HTTP
    public class HttpsProtocolHandler : HttpProtocolHandler
    {
        // Same implementation as HTTP, just with different protocol name
    }

    // FTP Protocol Handler 
    public class FtpProtocolHandler : BaseProtocolHandler
    {
        public override async Task<bool> DeserializeAsync(PacketContainer packet)
        {
            try
            {
                byte[] data = GetPayloadData(packet);
                if (data == null || data.Length == 0)
                    return false;

                string ftpContent = Encoding.ASCII.GetString(data);

                // Basic FTP command/response parsing
                var ftpMessage = new FtpMessage();

                // Check if it's a command or response based on port
                // FTP commands come from client to server (port 21)
                // FTP responses go from server to client
                if (packet.DestinationPort == 21)
                {
                    ftpMessage.IsCommand = true;

                    // Parse command - simple parse of the first word
                    int endOfCommand = ftpContent.IndexOf(' ');
                    if (endOfCommand > 0)
                    {
                        ftpMessage.Command = ftpContent.Substring(0, endOfCommand).Trim();
                        ftpMessage.Argument = ftpContent.Substring(endOfCommand + 1).Trim();
                    }
                    else
                    {
                        // Command with no argument
                        ftpMessage.Command = ftpContent.Trim();
                    }
                }
                else
                {
                    ftpMessage.IsCommand = false;

                    // Parse response code (first 3 digits)
                    if (ftpContent.Length >= 3 && int.TryParse(ftpContent.Substring(0, 3), out int code))
                    {
                        ftpMessage.ResponseCode = code;
                        ftpMessage.ResponseText = ftpContent.Substring(3).Trim();
                    }
                    else
                    {
                        // Couldn't parse response code
                        return false;
                    }
                }

                packet.DeserializedData = ftpMessage;
                packet.DeserializedType = typeof(FtpMessage);

                return true;
            }
            catch (Exception ex)
            {
                packet.ErrorMessages.Add($"FTP deserialization error: {ex.Message}");
                return false;
            }
        }

        public override async Task<bool> SerializeAsync(PacketContainer packet)
        {
            try
            {
                if (packet.DeserializedData is FtpMessage ftpMessage)
                {
                    string serialized;

                    if (ftpMessage.IsCommand)
                    {
                        serialized = string.IsNullOrEmpty(ftpMessage.Argument)
                            ? $"{ftpMessage.Command}\r\n"
                            : $"{ftpMessage.Command} {ftpMessage.Argument}\r\n";
                    }
                    else
                    {
                        serialized = $"{ftpMessage.ResponseCode} {ftpMessage.ResponseText}\r\n";
                    }

                    packet.ReserializedData = Encoding.ASCII.GetBytes(serialized);
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                packet.ErrorMessages.Add($"FTP serialization error: {ex.Message}");
                return false;
            }
        }
    }

    // SMTP Protocol Handler
    public class SmtpProtocolHandler : BaseProtocolHandler
    {
        public override async Task<bool> DeserializeAsync(PacketContainer packet)
        {
            try
            {
                byte[] data = GetPayloadData(packet);
                if (data == null || data.Length == 0)
                    return false;

                string smtpContent = Encoding.ASCII.GetString(data);

                // Basic SMTP command/response parsing
                var smtpMessage = new SmtpMessage();

                // Check if it's a command or response
                // SMTP commands are typically sent to port 25
                if (packet.DestinationPort == 25 || packet.DestinationPort == 587 || packet.DestinationPort == 465)
                {
                    smtpMessage.IsCommand = true;

                    // Parse command
                    int endOfCommand = smtpContent.IndexOf(' ');
                    if (endOfCommand > 0)
                    {
                        smtpMessage.Command = smtpContent.Substring(0, endOfCommand).Trim();
                        smtpMessage.Argument = smtpContent.Substring(endOfCommand + 1).Trim();
                    }
                    else
                    {
                        // Command with no argument
                        smtpMessage.Command = smtpContent.Trim();
                    }
                }
                else
                {
                    smtpMessage.IsCommand = false;

                    // Parse response code (first 3 digits)
                    if (smtpContent.Length >= 3 && int.TryParse(smtpContent.Substring(0, 3), out int code))
                    {
                        smtpMessage.ResponseCode = code;
                        smtpMessage.ResponseText = smtpContent.Substring(4).Trim(); // Skip code and space
                    }
                    else
                    {
                        // Couldn't parse response code
                        return false;
                    }
                }

                packet.DeserializedData = smtpMessage;
                packet.DeserializedType = typeof(SmtpMessage);

                return true;
            }
            catch (Exception ex)
            {
                packet.ErrorMessages.Add($"SMTP deserialization error: {ex.Message}");
                return false;
            }
        }

        public override async Task<bool> SerializeAsync(PacketContainer packet)
        {
            try
            {
                if (packet.DeserializedData is SmtpMessage smtpMessage)
                {
                    string serialized;

                    if (smtpMessage.IsCommand)
                    {
                        serialized = string.IsNullOrEmpty(smtpMessage.Argument)
                            ? $"{smtpMessage.Command}\r\n"
                            : $"{smtpMessage.Command} {smtpMessage.Argument}\r\n";
                    }
                    else
                    {
                        serialized = $"{smtpMessage.ResponseCode} {smtpMessage.ResponseText}\r\n";
                    }

                    packet.ReserializedData = Encoding.ASCII.GetBytes(serialized);
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                packet.ErrorMessages.Add($"SMTP serialization error: {ex.Message}");
                return false;
            }
        }
    }

    // DNS Protocol Handler
    public class DnsProtocolHandler : BaseProtocolHandler
    {
        public override async Task<bool> DeserializeAsync(PacketContainer packet)
        {
            try
            {
                byte[] data = GetPayloadData(packet);
                if (data == null || data.Length < 12) // DNS header is at least 12 bytes
                    return false;

                // Basic DNS packet parsing
                var dnsMessage = new DnsMessage();

                // Parse DNS header
                // Extract transaction ID (first 2 bytes)
                dnsMessage.TransactionId = (ushort)((data[0] << 8) | data[1]);

                // Extract flags (next 2 bytes)
                ushort flags = (ushort)((data[2] << 8) | data[3]);
                dnsMessage.IsQuery = (flags & 0x8000) == 0;
                dnsMessage.OperationCode = (byte)((flags >> 11) & 0xF);
                dnsMessage.IsAuthoritative = (flags & 0x0400) != 0;
                dnsMessage.IsTruncated = (flags & 0x0200) != 0;
                dnsMessage.RecursionDesired = (flags & 0x0100) != 0;
                dnsMessage.RecursionAvailable = (flags & 0x0080) != 0;
                dnsMessage.ResponseCode = (byte)(flags & 0xF);

                // Extract counts
                dnsMessage.QuestionCount = (ushort)((data[4] << 8) | data[5]);
                dnsMessage.AnswerCount = (ushort)((data[6] << 8) | data[7]);
                dnsMessage.AuthorityCount = (ushort)((data[8] << 8) | data[9]);
                dnsMessage.AdditionalCount = (ushort)((data[10] << 8) | data[11]);

                // DNS parsing is complex due to compression and variable length fields
                // For this simplified implementation, we'll just store the raw data
                dnsMessage.RawData = data;

                packet.DeserializedData = dnsMessage;
                packet.DeserializedType = typeof(DnsMessage);

                return true;
            }
            catch (Exception ex)
            {
                packet.ErrorMessages.Add($"DNS deserialization error: {ex.Message}");
                return false;
            }
        }

        public override async Task<bool> SerializeAsync(PacketContainer packet)
        {
            try
            {
                if (packet.DeserializedData is DnsMessage dnsMessage)
                {
                    // For this simplified implementation, just return the raw data
                    // In a real implementation, you would rebuild the packet
                    packet.ReserializedData = dnsMessage.RawData;
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                packet.ErrorMessages.Add($"DNS serialization error: {ex.Message}");
                return false;
            }
        }
    }

    // MQTT Protocol Handler
    public class MqttProtocolHandler : BaseProtocolHandler
    {
        public override async Task<bool> DeserializeAsync(PacketContainer packet)
        {
            try
            {
                byte[] data = GetPayloadData(packet);
                if (data == null || data.Length < 2) // MQTT requires at least 2 bytes
                    return false;

                // Basic MQTT packet parsing
                var mqttMessage = new MqttMessage();

                // First byte contains message type and flags
                byte firstByte = data[0];
                mqttMessage.MessageType = (byte)((firstByte >> 4) & 0x0F); // Upper 4 bits
                mqttMessage.Flags = (byte)(firstByte & 0x0F); // Lower 4 bits

                // Second byte starts the remaining length
                // MQTT has a variable length encoding which can be up to 4 bytes
                // For simplicity, we'll just store the raw message
                mqttMessage.RawData = data;

                // Identify common MQTT message types
                switch (mqttMessage.MessageType)
                {
                    case 1:
                        mqttMessage.MessageTypeName = "CONNECT";
                        break;
                    case 2:
                        mqttMessage.MessageTypeName = "CONNACK";
                        break;
                    case 3:
                        mqttMessage.MessageTypeName = "PUBLISH";
                        break;
                    case 4:
                        mqttMessage.MessageTypeName = "PUBACK";
                        break;
                    case 8:
                        mqttMessage.MessageTypeName = "SUBSCRIBE";
                        break;
                    case 9:
                        mqttMessage.MessageTypeName = "SUBACK";
                        break;
                    case 12:
                        mqttMessage.MessageTypeName = "PINGREQ";
                        break;
                    case 13:
                        mqttMessage.MessageTypeName = "PINGRESP";
                        break;
                    case 14:
                        mqttMessage.MessageTypeName = "DISCONNECT";
                        break;
                    default:
                        mqttMessage.MessageTypeName = $"UNKNOWN({mqttMessage.MessageType})";
                        break;
                }

                packet.DeserializedData = mqttMessage;
                packet.DeserializedType = typeof(MqttMessage);

                return true;
            }
            catch (Exception ex)
            {
                packet.ErrorMessages.Add($"MQTT deserialization error: {ex.Message}");
                return false;
            }
        }

        public override async Task<bool> SerializeAsync(PacketContainer packet)
        {
            try
            {
                if (packet.DeserializedData is MqttMessage mqttMessage)
                {
                    // For this simplified implementation, just return the raw data
                    packet.ReserializedData = mqttMessage.RawData;
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                packet.ErrorMessages.Add($"MQTT serialization error: {ex.Message}");
                return false;
            }
        }
    }

    // SSH Protocol Handler
    public class SshProtocolHandler : BaseProtocolHandler
    {
        public override async Task<bool> DeserializeAsync(PacketContainer packet)
        {
            try
            {
                byte[] data = GetPayloadData(packet);
                if (data == null || data.Length == 0)
                    return false;

                // Basic SSH packet parsing
                var sshMessage = new SshMessage();

                // Try to detect if this is a banner/initial message
                if (data.Length > 4 && Encoding.ASCII.GetString(data, 0, 4) == "SSH-")
                {
                    sshMessage.MessageType = "BANNER";
                    sshMessage.IsBanner = true;

                    // Extract the version info
                    string bannerText = Encoding.ASCII.GetString(data).Trim();
                    sshMessage.BannerText = bannerText;

                    // Parse SSH version if possible
                    var parts = bannerText.Split('-');
                    if (parts.Length >= 3)
                    {
                        sshMessage.SshVersion = parts[1];
                        var softwareAndComments = parts[2].Split(' ');
                        sshMessage.SoftwareVersion = softwareAndComments[0];
                    }
                }
                else
                {
                    // For binary SSH packets, we need to know the encryption state
                    // If the packet was successfully decrypted, we could parse it further
                    // For now, we'll just classify it based on what we can determine
                    if (packet.WasDecrypted)
                    {
                        // We'd need to look at the message code to determine type
                        sshMessage.MessageType = "ENCRYPTED(DECRYPTED)";
                    }
                    else
                    {
                        sshMessage.MessageType = "ENCRYPTED";
                    }

                    sshMessage.IsBanner = false;
                }

                // Store raw data for potential forwarding
                sshMessage.RawData = data;

                packet.DeserializedData = sshMessage;
                packet.DeserializedType = typeof(SshMessage);

                return true;
            }
            catch (Exception ex)
            {
                packet.ErrorMessages.Add($"SSH deserialization error: {ex.Message}");
                return false;
            }
        }

        public override async Task<bool> SerializeAsync(PacketContainer packet)
        {
            try
            {
                if (packet.DeserializedData is SshMessage sshMessage)
                {
                    if (sshMessage.IsBanner)
                    {
                        // For banner messages, we can modify them if needed
                        packet.ReserializedData = Encoding.ASCII.GetBytes(sshMessage.BannerText + "\r\n");
                    }
                    else
                    {
                        // For other messages, just use the raw data
                        packet.ReserializedData = sshMessage.RawData;
                    }

                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                packet.ErrorMessages.Add($"SSH serialization error: {ex.Message}");
                return false;
            }
        }
    }

    // RTP Protocol Handler (stub implementation)
    public class RtpProtocolHandler : BaseProtocolHandler
    {
        public override async Task<bool> DeserializeAsync(PacketContainer packet)
        {
            try
            {
                byte[] data = GetPayloadData(packet);
                if (data == null || data.Length < 12) // Minimum RTP header size
                    return false;

                // Basic RTP header parsing
                var rtpMessage = new RtpMessage();

                // First byte: version, padding, extension, CSRC count
                byte firstByte = data[0];
                rtpMessage.Version = (byte)((firstByte >> 6) & 0x03); // 2 bits
                rtpMessage.HasPadding = ((firstByte >> 5) & 0x01) == 1; // 1 bit
                rtpMessage.HasExtension = ((firstByte >> 4) & 0x01) == 1; // 1 bit
                rtpMessage.CsrcCount = (byte)(firstByte & 0x0F); // 4 bits

                // Second byte: marker, payload type
                byte secondByte = data[1];
                rtpMessage.HasMarker = ((secondByte >> 7) & 0x01) == 1; // 1 bit
                rtpMessage.PayloadType = (byte)(secondByte & 0x7F); // 7 bits

                // Sequence number (2 bytes)
                rtpMessage.SequenceNumber = (ushort)((data[2] << 8) | data[3]);

                // Timestamp (4 bytes)
                rtpMessage.Timestamp = (uint)((data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7]);

                // SSRC (4 bytes)
                rtpMessage.SynchronizationSource = (uint)((data[8] << 24) | (data[9] << 16) | (data[10] << 8) | data[11]);

                // Store raw data for potential forwarding
                rtpMessage.RawData = data;

                packet.DeserializedData = rtpMessage;
                packet.DeserializedType = typeof(RtpMessage);

                return true;
            }
            catch (Exception ex)
            {
                packet.ErrorMessages.Add($"RTP deserialization error: {ex.Message}");
                return false;
            }
        }

        public override async Task<bool> SerializeAsync(PacketContainer packet)
        {
            try
            {
                if (packet.DeserializedData is RtpMessage rtpMessage)
                {
                    // In a real implementation, we would rebuild the packet
                    // For now, just return the raw data
                    packet.ReserializedData = rtpMessage.RawData;
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                packet.ErrorMessages.Add($"RTP serialization error: {ex.Message}");
                return false;
            }
        }
    }

    // SIP Protocol Handler
    public class SipProtocolHandler : BaseProtocolHandler
    {
        public override async Task<bool> DeserializeAsync(PacketContainer packet)
        {
            try
            {
                byte[] data = GetPayloadData(packet);
                if (data == null || data.Length == 0)
                    return false;

                string sipContent = Encoding.ASCII.GetString(data);

                // Basic SIP message parsing
                var sipMessage = new SipMessage();

                // Split into lines
                string[] lines = sipContent.Split(new[] { "\r\n" }, StringSplitOptions.None);

                if (lines.Length == 0)
                    return false;

                // Parse first line to determine if request or response
                string firstLine = lines[0];

                if (firstLine.StartsWith("SIP/"))
                {
                    // It's a response
                    sipMessage.IsRequest = false;

                    // Parse response line (e.g., "SIP/2.0 200 OK")
                    string[] parts = firstLine.Split(new[] { ' ' }, 3);
                    if (parts.Length >= 3)
                    {
                        sipMessage.Version = parts[0];
                        sipMessage.StatusCode = int.Parse(parts[1]);
                        sipMessage.ReasonPhrase = parts[2];
                    }
                }
                else
                {
                    // It's a request
                    sipMessage.IsRequest = true;

                    // Parse request line (e.g., "INVITE sip:user@example.com SIP/2.0")
                    string[] parts = firstLine.Split(' ');
                    if (parts.Length >= 3)
                    {
                        sipMessage.Method = parts[0];
                        sipMessage.RequestUri = parts[1];
                        sipMessage.Version = parts[2];
                    }
                }

                // Parse headers
                for (int i = 1; i < lines.Length; i++)
                {
                    string line = lines[i];

                    // Empty line indicates end of headers
                    if (string.IsNullOrEmpty(line))
                    {
                        // The rest is the body
                        if (i + 1 < lines.Length)
                        {
                            sipMessage.Body = string.Join("\r\n", lines.Skip(i + 1));
                        }
                        break;
                    }

                    // Parse header
                    int colonPos = line.IndexOf(':');
                    if (colonPos > 0)
                    {
                        string name = line.Substring(0, colonPos).Trim();
                        string value = line.Substring(colonPos + 1).Trim();
                        sipMessage.Headers[name] = value;
                    }
                }

                packet.DeserializedData = sipMessage;
                packet.DeserializedType = typeof(SipMessage);

                return true;
            }
            catch (Exception ex)
            {
                packet.ErrorMessages.Add($"SIP deserialization error: {ex.Message}");
                return false;
            }
        }

        public override async Task<bool> SerializeAsync(PacketContainer packet)
        {
            try
            {
                if (packet.DeserializedData is SipMessage sipMessage)
                {
                    var sb = new StringBuilder();

                    // Build first line
                    if (sipMessage.IsRequest)
                    {
                        sb.AppendLine($"{sipMessage.Method} {sipMessage.RequestUri} {sipMessage.Version}");
                    }
                    else
                    {
                        sb.AppendLine($"{sipMessage.Version} {sipMessage.StatusCode} {sipMessage.ReasonPhrase}");
                    }

                    // Add headers
                    foreach (var header in sipMessage.Headers)
                    {
                        sb.AppendLine($"{header.Key}: {header.Value}");
                    }

                    // Add blank line and body
                    sb.AppendLine();
                    if (!string.IsNullOrEmpty(sipMessage.Body))
                    {
                        sb.Append(sipMessage.Body);
                    }

                    packet.ReserializedData = Encoding.ASCII.GetBytes(sb.ToString());
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                packet.ErrorMessages.Add($"SIP serialization error: {ex.Message}");
                return false;
            }
        }
    }

    // RTSP Protocol Handler
    public class RtspProtocolHandler : BaseProtocolHandler
    {
        public override async Task<bool> DeserializeAsync(PacketContainer packet)
        {
            try
            {
                byte[] data = GetPayloadData(packet);
                if (data == null || data.Length == 0)
                    return false;

                string rtspContent = Encoding.ASCII.GetString(data);

                // Basic RTSP message parsing (similar to HTTP/SIP)
                var rtspMessage = new RtspMessage();

                // Split into lines
                string[] lines = rtspContent.Split(new[] { "\r\n" }, StringSplitOptions.None);

                if (lines.Length == 0)
                    return false;

                // Parse first line to determine if request or response
                string firstLine = lines[0];

                if (firstLine.StartsWith("RTSP/"))
                {
                    // It's a response
                    rtspMessage.IsRequest = false;

                    // Parse response line (e.g., "RTSP/1.0 200 OK")
                    string[] parts = firstLine.Split(new[] { ' ' }, 3);
                    if (parts.Length >= 3)
                    {
                        rtspMessage.Version = parts[0];
                        rtspMessage.StatusCode = int.Parse(parts[1]);
                        rtspMessage.ReasonPhrase = parts[2];
                    }
                }
                else
                {
                    // It's a request
                    rtspMessage.IsRequest = true;

                    // Parse request line (e.g., "DESCRIBE rtsp://example.com/stream RTSP/1.0")
                    string[] parts = firstLine.Split(' ');
                    if (parts.Length >= 3)
                    {
                        rtspMessage.Method = parts[0];
                        rtspMessage.RequestUri = parts[1];
                        rtspMessage.Version = parts[2];
                    }
                }

                // Parse headers
                for (int i = 1; i < lines.Length; i++)
                {
                    string line = lines[i];

                    // Empty line indicates end of headers
                    if (string.IsNullOrEmpty(line))
                    {
                        // The rest is the body
                        if (i + 1 < lines.Length)
                        {
                            rtspMessage.Body = string.Join("\r\n", lines.Skip(i + 1));
                        }
                        break;
                    }

                    // Parse header
                    int colonPos = line.IndexOf(':');
                    if (colonPos > 0)
                    {
                        string name = line.Substring(0, colonPos).Trim();
                        string value = line.Substring(colonPos + 1).Trim();
                        rtspMessage.Headers[name] = value;
                    }
                }

                packet.DeserializedData = rtspMessage;
                packet.DeserializedType = typeof(RtspMessage);

                return true;
            }
            catch (Exception ex)
            {
                packet.ErrorMessages.Add($"RTSP deserialization error: {ex.Message}");
                return false;
            }
        }

        public override async Task<bool> SerializeAsync(PacketContainer packet)
        {
            try
            {
                if (packet.DeserializedData is RtspMessage rtspMessage)
                {
                    var sb = new StringBuilder();

                    // Build first line
                    if (rtspMessage.IsRequest)
                    {
                        sb.AppendLine($"{rtspMessage.Method} {rtspMessage.RequestUri} {rtspMessage.Version}");
                    }
                    else
                    {
                        sb.AppendLine($"{rtspMessage.Version} {rtspMessage.StatusCode} {rtspMessage.ReasonPhrase}");
                    }

                    // Add headers
                    foreach (var header in rtspMessage.Headers)
                    {
                        sb.AppendLine($"{header.Key}: {header.Value}");
                    }

                    // Add blank line and body
                    sb.AppendLine();
                    if (!string.IsNullOrEmpty(rtspMessage.Body))
                    {
                        sb.Append(rtspMessage.Body);
                    }

                    packet.ReserializedData = Encoding.ASCII.GetBytes(sb.ToString());
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                packet.ErrorMessages.Add($"RTSP serialization error: {ex.Message}");
                return false;
            }
        }
    }

    // QUIC Protocol Handler
    public class QuicProtocolHandler : BaseProtocolHandler
    {
        public override async Task<bool> DeserializeAsync(PacketContainer packet)
        {
            // QUIC parsing is quite complex, so this is a simplified placeholder
            try
            {
                byte[] data = GetPayloadData(packet);
                if (data == null || data.Length < 5) // Minimum expected QUIC header size
                    return false;

                var quicMessage = new QuicMessage
                {
                    RawData = data,
                    FirstByte = data[0],
                    // Try to determine if it's an initial packet or another type
                    IsInitial = (data[0] & 0xC0) == 0xC0
                };

                packet.DeserializedData = quicMessage;
                packet.DeserializedType = typeof(QuicMessage);

                return true;
            }
            catch (Exception ex)
            {
                packet.ErrorMessages.Add($"QUIC deserialization error: {ex.Message}");
                return false;
            }
        }

        public override async Task<bool> SerializeAsync(PacketContainer packet)
        {
            try
            {
                if (packet.DeserializedData is QuicMessage quicMessage)
                {
                    // In a real implementation, we would modify and rebuild the packet
                    // For now, just return the raw data
                    packet.ReserializedData = quicMessage.RawData;
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                packet.ErrorMessages.Add($"QUIC serialization error: {ex.Message}");
                return false;
            }
        }
    }

    // AMQP Protocol Handler
    public class AmqpProtocolHandler : BaseProtocolHandler
    {
        public override async Task<bool> DeserializeAsync(PacketContainer packet)
        {
            try
            {
                byte[] data = GetPayloadData(packet);
                if (data == null || data.Length < 8) // Minimum AMQP frame size
                    return false;

                var amqpMessage = new AmqpMessage
                {
                    RawData = data
                };

                // Check for protocol header (protocol identification)
                if (data.Length >= 8 && data[0] == (byte)'A' && data[1] == (byte)'M' &&
                    data[2] == (byte)'Q' && data[3] == (byte)'P')
                {
                    amqpMessage.IsProtocolHeader = true;
                    amqpMessage.ProtocolId = data[4];
                    amqpMessage.MajorVersion = data[5];
                    amqpMessage.MinorVersion = data[6];
                    amqpMessage.Revision = data[7];
                }
                else
                {
                    // Regular AMQP frame
                    amqpMessage.IsProtocolHeader = false;

                    // Parse frame header (8 bytes)
                    if (data.Length >= 8)
                    {
                        amqpMessage.DataOffset = data[0]; // Data offset (multiply by 4 to get actual offset)
                        amqpMessage.FrameType = data[1]; // Frame type
                        // Bytes 2-3: Channel
                        amqpMessage.Channel = (ushort)((data[2] << 8) | data[3]);
                        // Bytes 4-7: Frame size
                        amqpMessage.FrameSize = (uint)((data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7]);
                    }
                }

                packet.DeserializedData = amqpMessage;
                packet.DeserializedType = typeof(AmqpMessage);

                return true;
            }
            catch (Exception ex)
            {
                packet.ErrorMessages.Add($"AMQP deserialization error: {ex.Message}");
                return false;
            }
        }

        public override async Task<bool> SerializeAsync(PacketContainer packet)
        {
            try
            {
                if (packet.DeserializedData is AmqpMessage amqpMessage)
                {
                    // In a real implementation, we would modify and rebuild the packet
                    // For now, just return the raw data
                    packet.ReserializedData = amqpMessage.RawData;
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                packet.ErrorMessages.Add($"AMQP serialization error: {ex.Message}");
                return false;
            }
        }
    }

    // Custom Binary Protocol Handler
    public class CustomBinaryProtocolHandler : BaseProtocolHandler
    {
        public override async Task<bool> DeserializeAsync(PacketContainer packet)
        {
            try
            {
                byte[] data = GetPayloadData(packet);
                if (data == null || data.Length == 0)
                    return false;

                // This handler is for custom binary protocols
                // We'll create a simple container for the raw data
                var binaryMessage = new BinaryMessage
                {
                    RawData = data,
                    Length = data.Length
                };

                // Try to identify some common patterns
                if (data.Length > 4)
                {
                    // Check for potential length-prefixed message
                    binaryMessage.PotentialMessageLength =
                        (uint)((data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]);

                    // Check if the potential length makes sense
                    if (binaryMessage.PotentialMessageLength == data.Length - 4)
                    {
                        binaryMessage.IsLengthPrefixed = true;
                    }
                }

                packet.DeserializedData = binaryMessage;
                packet.DeserializedType = typeof(BinaryMessage);

                return true;
            }
            catch (Exception ex)
            {
                packet.ErrorMessages.Add($"Binary protocol deserialization error: {ex.Message}");
                return false;
            }
        }

        public override async Task<bool> SerializeAsync(PacketContainer packet)
        {
            try
            {
                if (packet.DeserializedData is BinaryMessage binaryMessage)
                {
                    // In a real implementation, you might modify the binary data
                    // For now, just return the raw data
                    packet.ReserializedData = binaryMessage.RawData;
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                packet.ErrorMessages.Add($"Binary protocol serialization error: {ex.Message}");
                return false;
            }
        }
    }

    #endregion

    #region Decryption Providers

    // Base implementation for decryption providers
    public abstract class BaseDecryptionProvider : IDecryptionProvider
    {
        public abstract Task<bool> CanDecryptAsync(PacketContainer packet);
        public abstract Task<bool> DecryptAsync(PacketContainer packet, X509Certificate2Collection certificates, byte[] masterKey, Dictionary<string, SessionKeyInfo> sessionKeys);
    }

    // TLS Decryption Provider 
    public class TlsDecryptionProvider : BaseDecryptionProvider
    {
        public override async Task<bool> CanDecryptAsync(PacketContainer packet)
        {
            return packet.IsEncrypted &&
                   (packet.ApplicationProtocol == "TLS" || packet.ApplicationProtocol == "HTTPS") &&
                   packet.PayloadData != null && packet.PayloadData.Length > 0;
        }

        public override async Task<bool> DecryptAsync(PacketContainer packet, X509Certificate2Collection certificates, byte[] masterKey, Dictionary<string, SessionKeyInfo> sessionKeys)
        {
            // This is a simplified placeholder for TLS decryption
            // Real TLS decryption is very complex and requires:
            // 1. TLS handshake monitoring to capture key exchange
            // 2. Private key for server certificate (for RSA key exchange)
            // 3. Session keys extraction (or SSLKEYLOGFILE)

            try
            {
                // Check if we have session keys
                if (sessionKeys.Count > 0)
                {
                    // Look for client random in handshake messages
                    // This would require tracking TLS handshakes
                    // Not implemented in this simplified version

                    // Simulate a successful decryption for demo purposes
                    if (packet.ApplicationProtocol == "HTTPS" &&
                        packet.PayloadData.Length > 5 &&
                        (packet.PayloadData[0] == 0x17 || packet.PayloadData[0] == 0x16))
                    {
                        // This is just a placeholder to demonstrate the flow
                        // It doesn't actually decrypt anything
                        byte[] decryptedData = new byte[packet.PayloadData.Length - 5]; // Remove header
                        Array.Copy(packet.PayloadData, 5, decryptedData, 0, decryptedData.Length);

                        // Set placeholder data (in reality, this would be properly decrypted)
                        packet.WasDecrypted = true;

                        // Check if it looks like HTTP
                        if (decryptedData.Length > 4 &&
                            (decryptedData[0] == 'H' && decryptedData[1] == 'T' && decryptedData[2] == 'T' && decryptedData[3] == 'P'))
                        {
                            packet.ApplicationProtocol = "HTTP";
                            packet.PayloadData = decryptedData;
                            return true;
                        }

                        // Otherwise, it's some other application protocol
                        packet.PayloadData = decryptedData;
                        return true;
                    }
                }

                // Check if we have a private key in certificates
                foreach (var cert in certificates)
                {
                    if (cert.HasPrivateKey)
                    {
                        // In a real implementation, we would:
                        // 1. Extract the key exchange parameters from handshake
                        // 2. Decrypt the master secret using the private key
                        // 3. Derive session keys
                        // 4. Decrypt the record

                        // Simulate success
                        return true;
                    }
                }

                // No keys available
                packet.ErrorMessages.Add("TLS decryption failed: no suitable keys available");
                return false;
            }
            catch (Exception ex)
            {
                packet.ErrorMessages.Add($"TLS decryption error: {ex.Message}");
                return false;
            }
        }
    }

    // SSL Decryption Provider 
    public class SslDecryptionProvider : BaseDecryptionProvider
    {
        public override async Task<bool> CanDecryptAsync(PacketContainer packet)
        {
            return packet.IsEncrypted &&
                   (packet.ApplicationProtocol == "SSL" || packet.ApplicationProtocol == "HTTPS") &&
                   packet.PayloadData != null && packet.PayloadData.Length > 0;
        }

        public override async Task<bool> DecryptAsync(PacketContainer packet, X509Certificate2Collection certificates, byte[] masterKey, Dictionary<string, SessionKeyInfo> sessionKeys)
        {
            // Similar to TLS but for older SSL protocol
            // This is a placeholder implementation
            packet.WasDecrypted = false;
            packet.ErrorMessages.Add("SSL decryption not fully implemented");
            return false;
        }
    }

    // AES Decryption Provider 
    public class AesDecryptionProvider : BaseDecryptionProvider
    {
        public override async Task<bool> CanDecryptAsync(PacketContainer packet)
        {
            // Check if packet contains AES-encrypted data
            // This would require some protocol-specific knowledge
            return packet.IsEncrypted &&
                   packet.DecryptionKey != null &&
                   packet.InitializationVector != null;
        }

        public override async Task<bool> DecryptAsync(PacketContainer packet, X509Certificate2Collection certificates, byte[] masterKey, Dictionary<string, SessionKeyInfo> sessionKeys)
        {
            try
            {
                // Check if we have the necessary key material
                if (packet.DecryptionKey != null && packet.InitializationVector != null)
                {
                    using var aes = Aes.Create();
                    aes.Key = packet.DecryptionKey;
                    aes.IV = packet.InitializationVector;
                    aes.Mode = CipherMode.CBC; // Most common, but should adapt based on context

                    using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    // In a real implementation, we would handle padding correctly
                    try
                    {
                        using var ms = new MemoryStream();
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                        {
                            cs.Write(packet.PayloadData, 0, packet.PayloadData.Length);
                        }

                        packet.PayloadData = ms.ToArray();
                        packet.WasDecrypted = true;
                        return true;
                    }
                    catch (CryptographicException)
                    {
                        // Decryption failed, possibly wrong key or IV
                        packet.ErrorMessages.Add("AES decryption failed: incorrect key or IV");
                        return false;
                    }
                }

                packet.ErrorMessages.Add("AES decryption failed: missing key or IV");
                return false;
            }
            catch (Exception ex)
            {
                packet.ErrorMessages.Add($"AES decryption error: {ex.Message}");
                return false;
            }
        }
    }

    // ChaCha20 Decryption Provider
    public class ChaCha20DecryptionProvider : BaseDecryptionProvider
    {
        public override async Task<bool> CanDecryptAsync(PacketContainer packet)
        {
            // Similar checks to AES
            return packet.IsEncrypted &&
                   packet.DecryptionKey != null &&
                   packet.InitializationVector != null;
        }

        public override async Task<bool> DecryptAsync(PacketContainer packet, X509Certificate2Collection certificates, byte[] masterKey, Dictionary<string, SessionKeyInfo> sessionKeys)
        {
            // ChaCha20 implementation would go here
            // .NET doesn't have built-in ChaCha20, so a third-party library would be needed
            packet.ErrorMessages.Add("ChaCha20 decryption not implemented");
            return false;
        }
    }

    // RC4 Decryption Provider
    public class Rc4DecryptionProvider : BaseDecryptionProvider
    {
        public override async Task<bool> CanDecryptAsync(PacketContainer packet)
        {
            // RC4 doesn't use an IV
            return packet.IsEncrypted && packet.DecryptionKey != null;
        }

        public override async Task<bool> DecryptAsync(PacketContainer packet, X509Certificate2Collection certificates, byte[] masterKey, Dictionary<string, SessionKeyInfo> sessionKeys)
        {
            try
            {
                if (packet.DecryptionKey != null)
                {
                    // RC4 implementation
                    byte[] decrypted = Rc4Transform(packet.PayloadData, packet.DecryptionKey);
                    if (decrypted != null)
                    {
                        packet.PayloadData = decrypted;
                        packet.WasDecrypted = true;
                        return true;
                    }
                }

                packet.ErrorMessages.Add("RC4 decryption failed: missing key");
                return false;
            }
            catch (Exception ex)
            {
                packet.ErrorMessages.Add($"RC4 decryption error: {ex.Message}");
                return false;
            }
        }

        private byte[] Rc4Transform(byte[] data, byte[] key)
        {
            // Simple RC4 implementation
            byte[] s = new byte[256];
            byte[] result = new byte[data.Length];

            // Initialize S-box
            for (int i = 0; i < 256; i++)
            {
                s[i] = (byte)i;
            }

            // Key scheduling
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + s[i] + key[i % key.Length]) % 256;
                byte temp = s[i];
                s[i] = s[j];
                s[j] = temp;
            }

            // Stream generation and XOR with input
            int i2 = 0, j2 = 0;
            for (int k = 0; k < data.Length; k++)
            {
                i2 = (i2 + 1) % 256;
                j2 = (j2 + s[i2]) % 256;

                byte temp = s[i2];
                s[i2] = s[j2];
                s[j2] = temp;

                int keyStream = s[(s[i2] + s[j2]) % 256];
                result[k] = (byte)(data[k] ^ keyStream);
            }

            return result;
        }
    }

    // DTLS Decryption Provider 
    public class DtlsDecryptionProvider : BaseDecryptionProvider
    {
        public override async Task<bool> CanDecryptAsync(PacketContainer packet)
        {
            return packet.IsEncrypted &&
                   packet.TransportProtocol == "UDP" &&
                   packet.PayloadData != null &&
                   packet.PayloadData.Length > 13 &&
                   packet.PayloadData[0] >= 20 && packet.PayloadData[0] <= 23 &&
                   packet.PayloadData[1] == 254 && // DTLS 1.2 version
                   packet.PayloadData[2] == 253;
        }

        public override async Task<bool> DecryptAsync(PacketContainer packet, X509Certificate2Collection certificates, byte[] masterKey, Dictionary<string, SessionKeyInfo> sessionKeys)
        {
            // Similar to TLS but with adaptations for UDP
            packet.ErrorMessages.Add("DTLS decryption not fully implemented");
            return false;
        }
    }

    // WireGuard Decryption Provider
    public class WireGuardDecryptionProvider : BaseDecryptionProvider
    {
        public override async Task<bool> CanDecryptAsync(PacketContainer packet)
        {
            // WireGuard uses UDP and has specific packet formats
            return packet.IsEncrypted &&
                   packet.TransportProtocol == "UDP" &&
                   (packet.DestinationPort == 51820 || packet.SourcePort == 51820) && // Default WireGuard port
                   packet.PayloadData != null &&
                   packet.PayloadData.Length > 4;
        }

        public override async Task<bool> DecryptAsync(PacketContainer packet, X509Certificate2Collection certificates, byte[] masterKey, Dictionary<string, SessionKeyInfo> sessionKeys)
        {
            // WireGuard uses Noise Protocol and ChaCha20-Poly1305
            packet.ErrorMessages.Add("WireGuard decryption not implemented");
            return false;
        }
    }

    // OpenVPN Decryption Provider
    public class OpenvpnDecryptionProvider : BaseDecryptionProvider
    {
        public override async Task<bool> CanDecryptAsync(PacketContainer packet)
        {
            // OpenVPN can use TCP or UDP and various ports
            // This is a simplistic check
            return packet.IsEncrypted &&
                   (packet.DestinationPort == 1194 || packet.SourcePort == 1194) && // Default OpenVPN port
                   packet.PayloadData != null &&
                   packet.PayloadData.Length > 4;
        }

        public override async Task<bool> DecryptAsync(PacketContainer packet, X509Certificate2Collection certificates, byte[] masterKey, Dictionary<string, SessionKeyInfo> sessionKeys)
        {
            // OpenVPN can use various encryption algorithms
            packet.ErrorMessages.Add("OpenVPN decryption not implemented");
            return false;
        }
    }

    #endregion

    #region Message Data Classes

    // HTTP message class
    public class HttpMessage
    {
        public bool IsRequest { get; set; }

        // Request properties
        public string Method { get; set; }
        public string Path { get; set; }

        // Response properties
        public int StatusCode { get; set; }

        // Common properties
        public string HttpVersion { get; set; }
        public Dictionary<string, string> Headers { get; set; } = new Dictionary<string, string>();
        public string Body { get; set; }
    }

    // FTP message class
    public class FtpMessage
    {
        public bool IsCommand { get; set; }

        // Command properties
        public string Command { get; set; }
        public string Argument { get; set; }

        // Response properties
        public int ResponseCode { get; set; }
        public string ResponseText { get; set; }
    }

    // SMTP message class
    public class SmtpMessage
    {
        public bool IsCommand { get; set; }

        // Command properties
        public string Command { get; set; }
        public string Argument { get; set; }

        // Response properties
        public int ResponseCode { get; set; }
        public string ResponseText { get; set; }
    }

    // DNS message class
    public class DnsMessage
    {
        // DNS Header fields
        public ushort TransactionId { get; set; }
        public bool IsQuery { get; set; }
        public byte OperationCode { get; set; }
        public bool IsAuthoritative { get; set; }
        public bool IsTruncated { get; set; }
        public bool RecursionDesired { get; set; }
        public bool RecursionAvailable { get; set; }
        public byte ResponseCode { get; set; }

        // Section counts
        public ushort QuestionCount { get; set; }
        public ushort AnswerCount { get; set; }
        public ushort AuthorityCount { get; set; }
        public ushort AdditionalCount { get; set; }

        // Raw data for complex processing
        public byte[] RawData { get; set; }
    }

    // MQTT message class
    public class MqttMessage
    {
        public byte MessageType { get; set; }
        public string MessageTypeName { get; set; }
        public byte Flags { get; set; }
        public byte[] RawData { get; set; }
    }

    // SSH message class
    public class SshMessage
    {
        public string MessageType { get; set; }
        public bool IsBanner { get; set; }
        public string BannerText { get; set; }
        public string SshVersion { get; set; }
        public string SoftwareVersion { get; set; }
        public byte[] RawData { get; set; }
    }

    // RTP message class
    public class RtpMessage
    {
        public byte Version { get; set; }
        public bool HasPadding { get; set; }
        public bool HasExtension { get; set; }
        public byte CsrcCount { get; set; }
        public bool HasMarker { get; set; }
        public byte PayloadType { get; set; }
        public ushort SequenceNumber { get; set; }
        public uint Timestamp { get; set; }
        public uint SynchronizationSource { get; set; }
        public byte[] RawData { get; set; }
    }

    // SIP message class
    public class SipMessage
    {
        public bool IsRequest { get; set; }

        // Request properties
        public string Method { get; set; }
        public string RequestUri { get; set; }

        // Response properties
        public int StatusCode { get; set; }
        public string ReasonPhrase { get; set; }

        // Common properties
        public string Version { get; set; }
        public Dictionary<string, string> Headers { get; set; } = new Dictionary<string, string>();
        public string Body { get; set; }
    }

    // RTSP message class
    public class RtspMessage
    {
        public bool IsRequest { get; set; }

        // Request properties
        public string Method { get; set; }
        public string RequestUri { get; set; }

        // Response properties
        public int StatusCode { get; set; }
        public string ReasonPhrase { get; set; }

        // Common properties
        public string Version { get; set; }
        public Dictionary<string, string> Headers { get; set; } = new Dictionary<string, string>();
        public string Body { get; set; }
    }

    // QUIC message class
    public class QuicMessage
    {
        public byte FirstByte { get; set; }
        public bool IsInitial { get; set; }
        public byte[] RawData { get; set; }
    }

    // AMQP message class
    public class AmqpMessage
    {
        public bool IsProtocolHeader { get; set; }

        // Protocol header fields
        public byte ProtocolId { get; set; }
        public byte MajorVersion { get; set; }
        public byte MinorVersion { get; set; }
        public byte Revision { get; set; }

        // Frame header fields
        public byte DataOffset { get; set; }
        public byte FrameType { get; set; }
        public ushort Channel { get; set; }
        public uint FrameSize { get; set; }

        public byte[] RawData { get; set; }
    }

    // Binary message class
    public class BinaryMessage
    {
        public int Length { get; set; }
        public uint PotentialMessageLength { get; set; }
        public bool IsLengthPrefixed { get; set; }
        public byte[] RawData { get; set; }
    }

    #endregion
}