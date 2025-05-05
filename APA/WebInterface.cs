using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace AdvancedPacketAnalyzer
{
    // Simple HTTP web server implementation that doesn't rely on ASP.NET Core
    public class SimpleWebServer
    {
        private readonly HttpListener _listener;
        private readonly string _url;
        private readonly Thread _serverThread;
        private readonly ConcurrentQueue<PacketContainer> _packetBuffer = new ConcurrentQueue<PacketContainer>();
        private readonly Dictionary<string, int> _protocolStats = new Dictionary<string, int>();
        private readonly object _statsLock = new object();
        private int _totalPackets = 0;
        private int _encryptedPackets = 0;
        private int _decryptedPackets = 0;
        private bool _isRunning = true;

        // IP tracking and filtering
        private Dictionary<string, int> _ipAddressStats = new Dictionary<string, int>();
        private List<string> _activeIpAddresses = new List<string>();
        private string _selectedIpAddress = null;
        private bool _filterByIp = false;

        public SimpleWebServer(string url)
        {
            _url = url;
            _listener = new HttpListener();
            _listener.Prefixes.Add(url);

            // Initialize stats
            lock (_statsLock)
            {
                _protocolStats.Clear();
                _protocolStats.Add("HTTP", 0);
                _protocolStats.Add("HTTPS", 0);
                _protocolStats.Add("FTP", 0);
                _protocolStats.Add("SMTP", 0);
                _protocolStats.Add("DNS", 0);
                _protocolStats.Add("MQTT", 0);
                _protocolStats.Add("UDP", 0);
                _protocolStats.Add("TCP", 0);
                _protocolStats.Add("Other", 0);
            }

            // Create server thread
            _serverThread = new Thread(Listen);
            _serverThread.IsBackground = true;
        }

        public void Start()
        {
            try
            {
                _listener.Start();
                _serverThread.Start();
                Console.WriteLine($"Web interface started at {_url}");
                Console.WriteLine("Open the above URL in a browser to view the dashboard");

                // Start packet processing thread
                var processingThread = new Thread(ProcessPackets);
                processingThread.IsBackground = true;
                processingThread.Start();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error starting web server: {ex.Message}");
                Console.WriteLine("Make sure you're running as Administrator and port 8080 is available");
            }
        }

        public void Stop()
        {
            _isRunning = false;
            try
            {
                _listener.Stop();
                _listener.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error stopping web server: {ex.Message}");
            }
        }

        // Process any captured packets
        private void ProcessPackets()
        {
            while (_isRunning)
            {
                try
                {
                    Thread.Sleep(100); // Avoid thrashing CPU
                }
                catch (ThreadInterruptedException)
                {
                    break;
                }
            }
        }

        // Enqueue a packet for processing
        public void EnqueuePacket(PacketContainer packet)
        {
            // Update statistics
            lock (_statsLock)
            {
                _totalPackets++;

                if (packet.IsEncrypted)
                {
                    _encryptedPackets++;
                    if (packet.WasDecrypted)
                    {
                        _decryptedPackets++;
                    }
                }

                // Track IP addresses
                if (!string.IsNullOrEmpty(packet.SourceIp))
                {
                    if (!_ipAddressStats.ContainsKey(packet.SourceIp))
                    {
                        _ipAddressStats[packet.SourceIp] = 0;
                        _activeIpAddresses.Add(packet.SourceIp);
                    }
                    _ipAddressStats[packet.SourceIp]++;
                }

                if (!string.IsNullOrEmpty(packet.DestinationIp))
                {
                    if (!_ipAddressStats.ContainsKey(packet.DestinationIp))
                    {
                        _ipAddressStats[packet.DestinationIp] = 0;
                        _activeIpAddresses.Add(packet.DestinationIp);
                    }
                    _ipAddressStats[packet.DestinationIp]++;
                }

                // Update protocol stats
                if (!string.IsNullOrEmpty(packet.ApplicationProtocol) && _protocolStats.ContainsKey(packet.ApplicationProtocol))
                {
                    _protocolStats[packet.ApplicationProtocol]++;
                }
                else if (!string.IsNullOrEmpty(packet.TransportProtocol) && _protocolStats.ContainsKey(packet.TransportProtocol))
                {
                    _protocolStats[packet.TransportProtocol]++;
                }
                else
                {
                    _protocolStats["Other"]++;
                }
            }

            // Filter packets if filtering is enabled
            bool shouldKeep = !_filterByIp ||
                             _selectedIpAddress == null ||
                             packet.SourceIp == _selectedIpAddress ||
                             packet.DestinationIp == _selectedIpAddress;

            if (shouldKeep)
            {
                // Keep only the last 1000 packets
                while (_packetBuffer.Count > 1000)
                {
                    _packetBuffer.TryDequeue(out var _);
                }

                // Add new packet
                _packetBuffer.Enqueue(packet);
            }
        }

        // Main web server loop
        private void Listen()
        {
            while (_isRunning)
            {
                try
                {
                    var context = _listener.GetContext();
                    ThreadPool.QueueUserWorkItem((_) => ProcessRequest(context));
                }
                catch (Exception ex)
                {
                    if (_isRunning)
                    {
                        Console.WriteLine($"Web server error: {ex.Message}");
                    }
                }
            }
        }

        // Process incoming HTTP requests
        private void ProcessRequest(HttpListenerContext context)
        {
            try
            {
                string url = context.Request.Url.LocalPath;

                switch (url)
                {
                    case "/":
                    case "/index.html":
                        ServeHtmlFile(context);
                        break;

                    case "/api/stats":
                        ServeStats(context);
                        break;

                    case "/api/packets":
                        ServePackets(context);
                        break;

                    case "/api/devices":
                        ServeDevices(context);
                        break;

                    case "/api/ipaddresses":
                        ServeIpAddresses(context);
                        break;

                    case "/api/command":
                        HandleCommand(context);
                        break;

                    case "/chartjs":
                        ServeChartJs(context);
                        break;

                    default:
                        context.Response.StatusCode = 404;
                        context.Response.Close();
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error processing request: {ex.Message}");
                try
                {
                    context.Response.StatusCode = 500;
                    context.Response.Close();
                }
                catch
                {
                    // Ignore any errors from closing the response
                }
            }
        }

        // Serve the main HTML file
        private void ServeHtmlFile(HttpListenerContext context)
        {
            string html = GetHtmlContent();

            context.Response.ContentType = "text/html";
            context.Response.ContentEncoding = Encoding.UTF8;

            using (var writer = new StreamWriter(context.Response.OutputStream))
            {
                writer.Write(html);
            }
        }

        // Serve statistics
        private void ServeStats(HttpListenerContext context)
        {
            var stats = new
            {
                TotalPackets = _totalPackets,
                EncryptedPackets = _encryptedPackets,
                DecryptedPackets = _decryptedPackets,
                ProtocolStats = _protocolStats
            };

            string json = JsonConvert.SerializeObject(stats);

            context.Response.ContentType = "application/json";
            context.Response.ContentEncoding = Encoding.UTF8;

            using (var writer = new StreamWriter(context.Response.OutputStream))
            {
                writer.Write(json);
            }
        }

        // Serve packet data
        private void ServePackets(HttpListenerContext context)
        {
            // Get the most recent 50 packets
            var packets = _packetBuffer.ToArray().Reverse().Take(50).Select(p => new
            {
                Id = Guid.NewGuid().ToString(),
                SourceIp = p.SourceIp,
                DestinationIp = p.DestinationIp,
                SourcePort = p.SourcePort,
                DestinationPort = p.DestinationPort,
                TransportProtocol = p.TransportProtocol,
                ApplicationProtocol = p.ApplicationProtocol,
                Length = p.PacketLength,
                IsEncrypted = p.IsEncrypted,
                WasDecrypted = p.WasDecrypted,
                Time = p.CaptureTime.ToString("HH:mm:ss.fff"),
                Status = p.PacketStatus.ToString(),
                HasErrors = p.HasErrors,
                AdditionalInfo = p.AdditionalInfo
            }).ToList();

            string json = JsonConvert.SerializeObject(packets);

            context.Response.ContentType = "application/json";
            context.Response.ContentEncoding = Encoding.UTF8;

            using (var writer = new StreamWriter(context.Response.OutputStream))
            {
                writer.Write(json);
            }
        }

        // Serve IP addresses
        private void ServeIpAddresses(HttpListenerContext context)
        {
            var ipData = new
            {
                ActiveIps = _activeIpAddresses,
                IpStats = _ipAddressStats,
                SelectedIp = _selectedIpAddress,
                FilterActive = _filterByIp
            };

            string json = JsonConvert.SerializeObject(ipData);

            context.Response.ContentType = "application/json";
            context.Response.ContentEncoding = Encoding.UTF8;

            using (var writer = new StreamWriter(context.Response.OutputStream))
            {
                writer.Write(json);
            }
        }

        // Serve device information
        private void ServeDevices(HttpListenerContext context)
        {
            try
            {
                var devices = Program.CaptureDevices.Select((d, index) => new
                {
                    Index = index,
                    Name = d?.Name ?? "unknown",
                    Description = d?.Description ?? d?.Name ?? "unknown device",
                    IsActive = d != null && d.Started
                }).ToList();

                string json = JsonConvert.SerializeObject(devices);

                context.Response.ContentType = "application/json";
                context.Response.ContentEncoding = Encoding.UTF8;

                using (var writer = new StreamWriter(context.Response.OutputStream))
                {
                    writer.Write(json);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in ServeDevices: {ex.Message}");
                // Return empty array instead of error
                using (var writer = new StreamWriter(context.Response.OutputStream))
                {
                    writer.Write("[]");
                }
            }
        }

        // Handle command requests
        private void HandleCommand(HttpListenerContext context)
        {
            if (context.Request.HttpMethod != "POST")
            {
                context.Response.StatusCode = 405;
                context.Response.Close();
                return;
            }

            string body;
            using (var reader = new StreamReader(context.Request.InputStream))
            {
                body = reader.ReadToEnd();
            }

            Console.WriteLine($"Received command: {body}");

            var command = JsonConvert.DeserializeObject<CommandRequest>(body);
            CommandResult result = new CommandResult { Success = false, Message = "Unknown command" };

            try
            {
                switch (command?.Command?.ToLower())
                {
                    case "start":
                        result = StartCapturing(command.DeviceIndex);
                        break;
                    case "stop":
                        result = StopCapturing(command.DeviceIndex);
                        break;
                    case "clearstats":
                        result = ClearStatistics();
                        break;
                    case "setipfilter":
                        result = SetIpFilter(command.IpAddress, command.Enable ?? false);
                        break;
                }
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = $"Error executing command: {ex.Message}";
                Console.WriteLine($"Command error: {ex.Message}");
            }

            string responseJson = JsonConvert.SerializeObject(result);
            Console.WriteLine($"Sending response: {responseJson}");

            context.Response.ContentType = "application/json";
            context.Response.ContentEncoding = Encoding.UTF8;

            using (var writer = new StreamWriter(context.Response.OutputStream))
            {
                writer.Write(responseJson);
            }
        }

        // Set IP filter
        private CommandResult SetIpFilter(string ipAddress, bool enableFilter)
        {
            try
            {
                lock (_statsLock)
                {
                    _selectedIpAddress = ipAddress;
                    _filterByIp = enableFilter;

                    // Clear packet buffer if filter changed
                    if (enableFilter)
                    {
                        while (_packetBuffer.TryDequeue(out var _)) { }
                    }
                }

                return new CommandResult
                {
                    Success = true,
                    Message = enableFilter
                        ? $"Now filtering packets for IP: {ipAddress}"
                        : "IP filtering disabled"
                };
            }
            catch (Exception ex)
            {
                return new CommandResult { Success = false, Message = $"Error setting IP filter: {ex.Message}" };
            }
        }

        // Serve Chart.js library
        private void ServeChartJs(HttpListenerContext context)
        {
            context.Response.Headers.Add("Location", "https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.7.0/chart.min.js");
            context.Response.StatusCode = 302;
            context.Response.Close();
        }

        // Start capturing on devices
        private CommandResult StartCapturing(int? deviceIndex)
        {
            try
            {
                if (!deviceIndex.HasValue)
                {
                    // Start all devices
                    foreach (var device in Program.CaptureDevices)
                    {
                        if (!device.Started)
                        {
                            device.StartCapture();
                        }
                    }
                    return new CommandResult { Success = true, Message = "Started all capture devices" };
                }
                else
                {
                    // Start specific device
                    if (deviceIndex.Value >= 0 && deviceIndex.Value < Program.CaptureDevices.Count)
                    {
                        var device = Program.CaptureDevices[deviceIndex.Value];
                        if (!device.Started)
                        {
                            device.StartCapture();
                        }
                        return new CommandResult { Success = true, Message = $"Started capture device: {device.Description}" };
                    }
                    else
                    {
                        return new CommandResult { Success = false, Message = "Invalid device index" };
                    }
                }
            }
            catch (Exception ex)
            {
                return new CommandResult { Success = false, Message = $"Error starting capture: {ex.Message}" };
            }
        }

        // Stop capturing on devices
        private CommandResult StopCapturing(int? deviceIndex)
        {
            try
            {
                if (!deviceIndex.HasValue)
                {
                    // Stop all devices
                    foreach (var device in Program.CaptureDevices)
                    {
                        if (device.Started)
                        {
                            device.StopCapture();
                        }
                    }
                    return new CommandResult { Success = true, Message = "Stopped all capture devices" };
                }
                else
                {
                    // Stop specific device
                    if (deviceIndex.Value >= 0 && deviceIndex.Value < Program.CaptureDevices.Count)
                    {
                        var device = Program.CaptureDevices[deviceIndex.Value];
                        if (device.Started)
                        {
                            device.StopCapture();
                        }
                        return new CommandResult { Success = true, Message = $"Stopped capture device: {device.Description}" };
                    }
                    else
                    {
                        return new CommandResult { Success = false, Message = "Invalid device index" };
                    }
                }
            }
            catch (Exception ex)
            {
                return new CommandResult { Success = false, Message = $"Error stopping capture: {ex.Message}" };
            }
        }

        // Clear statistics
        private CommandResult ClearStatistics()
        {
            try
            {
                lock (_statsLock)
                {
                    _totalPackets = 0;
                    _encryptedPackets = 0;
                    _decryptedPackets = 0;

                    foreach (var key in _protocolStats.Keys.ToList())
                    {
                        _protocolStats[key] = 0;
                    }

                    // Clear IP stats too
                    _ipAddressStats.Clear();
                    _activeIpAddresses.Clear();
                }

                // Clear packet buffer
                while (_packetBuffer.TryDequeue(out var _)) { }

                return new CommandResult { Success = true, Message = "Statistics cleared" };
            }
            catch (Exception ex)
            {
                return new CommandResult { Success = false, Message = $"Error clearing statistics: {ex.Message}" };
            }
        }

        // Get HTML content for the web interface
        private string GetHtmlContent()
        {
            return @"<!DOCTYPE html>
<html lang=""en"">
<head>
    <meta charset=""UTF-8"">
    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
    <title>Advanced Packet Analyzer Dashboard</title>
    <link href=""https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css"" rel=""stylesheet"">
    <style>
        :root {
            --primary: #1e88e5;
            --primary-dark: #0d47a1;
            --secondary: #7e57c2;
            --danger: #e53935;
            --success: #43a047;
            --warning: #ffb300;
            --dark: #212121;
            --light: #f5f5f5;
            --card-bg: rgba(33, 33, 33, 0.95);
            --text: #f5f5f5;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        body {
            background-color: #121212;
            color: var(--text);
            overflow-x: hidden;
        }
        
        /* Neon effect and animations */
        @keyframes glow {
            0% { box-shadow: 0 0 5px var(--primary), 0 0 10px var(--primary); }
            50% { box-shadow: 0 0 10px var(--primary), 0 0 20px var(--primary); }
            100% { box-shadow: 0 0 5px var(--primary), 0 0 10px var(--primary); }
        }
        
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        @keyframes slideIn {
            from { transform: translateX(-20px); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        
        @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
        
        /* Header */
        header {
            padding: 1rem 2rem;
            background-color: var(--dark);
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--primary);
            animation: glow 3s infinite;
        }
        
        .logo {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .logo h1 {
            font-size: 1.5rem;
            font-weight: 600;
            background: linear-gradient(45deg, var(--primary), var(--secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .logo i {
            color: var(--primary);
            font-size: 1.5rem;
        }
        
        .controls {
            display: flex;
            gap: 1rem;
        }
        
        .btn {
            padding: 0.5rem 1rem;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-weight: 500;
            transition: all 0.3s ease;
        }
        
        .btn:hover {
            transform: translateY(-2px);
        }
        
        .btn-primary {
            background-color: var(--primary);
            color: white;
        }
        
        .btn-danger {
            background-color: var(--danger);
            color: white;
        }
        
        .btn-success {
            background-color: var(--success);
            color: white;
        }
        
        /* Main Content */
        .container {
            padding: 1rem 2rem;
            display: grid;
            grid-template-columns: 1fr 3fr;
            gap: 1rem;
            max-width: 100%;
            overflow-x: hidden;
        }
        
        .stats-container {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }
        
        .card {
            background-color: var(--card-bg);
            border-radius: 8px;
            padding: 1rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            animation: fadeIn 0.5s ease;
        }
        
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 0.5rem;
            margin-bottom: 0.5rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .card-header h2 {
            font-size: 1.2rem;
            font-weight: 500;
        }
        
        .stat-boxes {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 0.5rem;
        }
        
        .stat-box {
            background-color: rgba(0, 0, 0, 0.3);
            border-radius: 4px;
            padding: 0.5rem;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            text-align: center;
            transition: all 0.3s ease;
        }
        
        .stat-box:hover {
            background-color: rgba(0, 0, 0, 0.5);
            transform: translateY(-2px);
        }
        
        .stat-value {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 0.25rem;
        }
        
        .stat-label {
            font-size: 0.75rem;
            opacity: 0.8;
        }
        
        /* Protocol Charts */
        .protocol-chart {
            width: 100%;
            height: 200px;
            margin-top: 1rem;
        }
        
        /* Device List */
        .device-list {
            margin-top: 0.5rem;
        }
        
        .device-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.5rem;
            border-radius: 4px;
            margin-bottom: 0.5rem;
            background-color: rgba(0, 0, 0, 0.3);
            animation: slideIn 0.3s ease;
        }
        
        .device-name {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .device-status {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background-color: var(--danger);
        }
        
        .device-status.active {
            background-color: var(--success);
        }
        
        /* Packet Visualizer */
        .packet-visualizer {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }
        
        .packet-stream {
            height: 150px;
            position: relative;
            background-color: rgba(0, 0, 0, 0.3);
            border-radius: 8px;
            overflow: hidden;
        }
        
        .packet {
            position: absolute;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background-color: var(--primary);
            animation: packet-move 3s linear forwards;
        }
        
        @keyframes packet-move {
            from { left: 0; }
            to { left: 100%; }
        }
        
        .packet.encrypted {
            background-color: var(--danger);
        }
        
        .packet.decrypted {
            background-color: var(--success);
        }
        
        /* Packet List */
        .packet-list {
            height: 400px;
            overflow-y: auto;
        }
        
        .packet-item {
            display: flex;
            justify-content: space-between;
            padding: 0.5rem;
            border-radius: 4px;
            margin-bottom: 0.5rem;
            background-color: rgba(0, 0, 0, 0.3);
            cursor: pointer;
            transition: all 0.3s ease;
            animation: slideIn 0.3s ease;
        }
        
        .packet-item:hover {
            background-color: rgba(0, 0, 0, 0.5);
        }
        
        .packet-info {
            display: flex;
            gap: 0.5rem;
        }
        
        .packet-protocol {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 60px;
            padding: 0.25rem;
            border-radius: 4px;
            background-color: var(--primary);
            font-size: 0.75rem;
            font-weight: 600;
        }
        
        .packet-protocol.http {
            background-color: var(--primary);
        }
        
        .packet-protocol.https {
            background-color: var(--secondary);
        }
        
        .packet-protocol.dns {
            background-color: var(--warning);
            color: var(--dark);
        }
        
        .packet-protocol.tcp {
            background-color: #26a69a;
        }
        
        .packet-protocol.udp {
            background-color: #9c27b0;
        }
        
        .packet-protocol.encrypted {
            background-color: var(--danger);
        }
        
        .packet-time {
            font-size: 0.75rem;
            opacity: 0.8;
        }
        
        /* Packet Details Modal */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.8);
            z-index: 1000;
            align-items: center;
            justify-content: center;
            animation: fadeIn 0.3s ease;
        }
        
        .modal-content {
            background-color: var(--card-bg);
            border-radius: 8px;
            width: 80%;
            max-width: 1000px;
            max-height: 80vh;
            overflow-y: auto;
            padding: 1rem;
            position: relative;
            animation: slideIn 0.3s ease;
        }
        
        .close-modal {
            position: absolute;
            top: 0.5rem;
            right: 0.5rem;
            font-size: 1.5rem;
            cursor: pointer;
            color: var(--text);
            transition: all 0.3s ease;
        }
        
        .close-modal:hover {
            color: var(--danger);
        }
        
        .packet-detail-header {
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .packet-detail-content {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1rem;
        }
        
        .detail-group {
            margin-bottom: 1rem;
        }
        
        .detail-group h3 {
            font-size: 1rem;
            margin-bottom: 0.5rem;
            color: var(--primary);
        }
        
        .detail-item {
            display: flex;
            justify-content: space-between;
            padding: 0.25rem 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }
        
        .detail-label {
            font-weight: 500;
        }
        
        .detail-value {
            opacity: 0.8;
        }
        
        .packet-payload {
            grid-column: span 2;
            background-color: rgba(0, 0, 0, 0.3);
            padding: 0.5rem;
            border-radius: 4px;
            font-family: 'Courier New', Courier, monospace;
            white-space: pre-wrap;
            overflow-x: auto;
        }
        
        /* IP Filter Styles */
        .ip-select {
            width: 100%;
            padding: 0.5rem;
            background-color: rgba(0, 0, 0, 0.3);
            color: var(--text);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 4px;
            margin-bottom: 0.5rem;
        }
        
        .filter-controls {
            display: flex;
            gap: 0.5rem;
            margin-bottom: 0.5rem;
        }
        
        .active-filter {
            padding: 0.5rem;
            background-color: rgba(0, 0, 0, 0.2);
            border-radius: 4px;
            border-left: 3px solid var(--success);
        }
        
        /* Utility Classes */
        .text-primary { color: var(--primary); }
        .text-danger { color: var(--danger); }
        .text-success { color: var(--success); }
        .text-warning { color: var(--warning); }
        
        .mt-1 { margin-top: 0.5rem; }
        .mt-2 { margin-top: 1rem; }
        
        /* Loading Spinner */
        .spinner {
            width: 40px;
            height: 40px;
            border: 4px solid rgba(255, 255, 255, 0.1);
            border-radius: 50%;
            border-top-color: var(--primary);
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }
        
        /* Network Graph */
        .network-graph {
            height: 200px;
            background-color: rgba(0, 0, 0, 0.3);
            border-radius: 8px;
            margin-top: 1rem;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            overflow: hidden;
        }
        
        .network-node {
            width: 30px;
            height: 30px;
            border-radius: 50%;
            background-color: rgba(30, 136, 229, 0.3);
            border: 2px solid var(--primary);
            position: absolute;
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 10;
            box-shadow: 0 0 10px var(--primary);
            animation: pulse 2s infinite;
        }
        
        .network-link {
            position: absolute;
            height: 2px;
            background: linear-gradient(90deg, var(--primary), transparent);
            z-index: 5;
            transform-origin: left center;
        }
        
        .network-packet {
            position: absolute;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background-color: var(--primary);
            z-index: 15;
        }
    </style>
</head>
<body>
    <header>
        <div class=""logo"">
            <i class=""fas fa-network-wired""></i>
            <h1>Advanced Packet Analyzer</h1>
        </div>
        <div class=""controls"">
            <button id=""startBtn"" class=""btn btn-success"">
                <i class=""fas fa-play""></i>
                Start Capture
            </button>
            <button id=""stopBtn"" class=""btn btn-danger"">
                <i class=""fas fa-stop""></i>
                Stop Capture
            </button>
            <button id=""clearBtn"" class=""btn btn-primary"">
                <i class=""fas fa-eraser""></i>
                Clear Data
            </button>
        </div>
    </header>
    
    <div class=""container"">
        <div class=""stats-container"">
            <div class=""card"">
                <div class=""card-header"">
                    <h2>Packet Statistics</h2>
                    <i class=""fas fa-chart-pie text-primary""></i>
                </div>
                <div class=""stat-boxes"">
                    <div class=""stat-box"">
                        <div id=""total-packets"" class=""stat-value"">0</div>
                        <div class=""stat-label"">Total Packets</div>
                    </div>
                    <div class=""stat-box"">
                        <div id=""encrypted-packets"" class=""stat-value"">0</div>
                        <div class=""stat-label"">Encrypted</div>
                    </div>
                    <div class=""stat-box"">
                        <div id=""decrypted-packets"" class=""stat-value"">0</div>
                        <div class=""stat-label"">Decrypted</div>
                    </div>
                    <div class=""stat-box"">
                        <div id=""error-packets"" class=""stat-value"">0</div>
                        <div class=""stat-label"">Errors</div>
                    </div>
                </div>
                <div class=""protocol-chart"">
                    <canvas id=""protocolChart""></canvas>
                </div>
            </div>
            
            <!-- IP Address Filter -->
            <div class=""card"">
                <div class=""card-header"">
                    <h2>IP Address Filter</h2>
                    <i class=""fas fa-filter text-primary""></i>
                </div>
                <div>
                    <select id=""ip-select"" class=""ip-select"">
                        <option value="""">Select IP Address</option>
                    </select>
                    <div class=""filter-controls"">
                        <button id=""apply-filter-btn"" class=""btn btn-primary"">
                            <i class=""fas fa-filter""></i> Filter by IP
                        </button>
                        <button id=""clear-filter-btn"" class=""btn btn-danger"">
                            <i class=""fas fa-times""></i> Clear Filter
                        </button>
                    </div>
                    <div id=""active-filter""></div>
                </div>
            </div>
            
            <div class=""card"">
                <div class=""card-header"">
                    <h2>Capture Devices</h2>
                    <i class=""fas fa-hdd text-primary""></i>
                </div>
                <div id=""device-list"" class=""device-list"">
                    <div class=""spinner""></div>
                </div>
            </div>
            
            <div class=""card"">
                <div class=""card-header"">
                    <h2>Network Graph</h2>
                    <i class=""fas fa-project-diagram text-primary""></i>
                </div>
                <div class=""network-graph"" id=""networkGraph"">
                    <!-- Network nodes and connections will be added dynamically -->
                </div>
            </div>
        </div>
        
        <div class=""packet-visualizer"">
            <div class=""card"">
                <div class=""card-header"">
                    <h2>Packet Flow</h2>
                    <i class=""fas fa-stream text-primary""></i>
                </div>
                <div class=""packet-stream"" id=""packetStream"">
                    <!-- Packets will flow here -->
                </div>
            </div>
            
            <div class=""card"">
                <div class=""card-header"">
                    <h2>Packet Capture</h2>
                    <i class=""fas fa-list text-primary""></i>
                </div>
                <div id=""packet-list"" class=""packet-list"">
                    <!-- Packet items will be added here -->
                </div>
            </div>
        </div>
    </div>
    
    <!-- Packet Details Modal -->
    <div id=""packetModal"" class=""modal"">
        <div class=""modal-content"">
            <span class=""close-modal"">&times;</span>
            <div class=""packet-detail-header"">
                <h2 id=""modal-title"">Packet Details</h2>
            </div>
            <div class=""packet-detail-content"" id=""packet-details"">
                <!-- Packet details will be loaded here -->
            </div>
        </div>
    </div>
    
    <!-- Scripts -->
    <script src=""https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.7.0/chart.min.js""></script>
    
    <script>
        // DOM Elements
        const startBtn = document.getElementById('startBtn');
        const stopBtn = document.getElementById('stopBtn');
        const clearBtn = document.getElementById('clearBtn');
        const packetList = document.getElementById('packet-list');
        const packetStream = document.getElementById('packetStream');
        const deviceList = document.getElementById('device-list');
        const totalPacketsEl = document.getElementById('total-packets');
        const encryptedPacketsEl = document.getElementById('encrypted-packets');
        const decryptedPacketsEl = document.getElementById('decrypted-packets');
        const errorPacketsEl = document.getElementById('error-packets');
        const packetModal = document.getElementById('packetModal');
        const closeModal = document.querySelector('.close-modal');
        const modalTitle = document.getElementById('modal-title');
        const packetDetails = document.getElementById('packet-details');
        const networkGraph = document.getElementById('networkGraph');
        
        // Protocol chart
        const protocolCtx = document.getElementById('protocolChart').getContext('2d');
        const protocolChart = new Chart(protocolCtx, {
            type: 'doughnut',
            data: {
                labels: ['HTTP', 'HTTPS', 'DNS', 'TCP', 'UDP', 'Other'],
                datasets: [{
                    data: [0, 0, 0, 0, 0, 0],
                    backgroundColor: [
                        '#1e88e5',
                        '#7e57c2',
                        '#ffb300',
                        '#26a69a',
                        '#9c27b0',
                        '#212121'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#f5f5f5'
                        }
                    }
                }
            }
        });
        
        // Last seen packets
        let lastSeenPackets = [];
        
        // Network nodes
        const networkNodes = {
            central: null,
            remotes: {}
        };
        
        // Initialize
        document.addEventListener('DOMContentLoaded', () => {
            // Load initial data
            loadDevices();
            loadIpAddresses();
            initNetworkGraph();
            
            // Start polling
            pollStats();
            pollPackets();
            setInterval(loadIpAddresses, 2000);
        });
        
        // Poll for statistics
        function pollStats() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(stats => {
                    updateStats(stats);
                })
                .catch(err => {
                    console.error('Error polling stats:', err);
                })
                .finally(() => {
                    // Poll again in 1 second
                    setTimeout(pollStats, 1000);
                });
        }
        
        // Poll for packets
        function pollPackets() {
            fetch('/api/packets')
                .then(response => response.json())
                .then(packets => {
                    // Find new packets
                    const newPackets = packets.filter(p => 
                        !lastSeenPackets.some(lp => lp.id === p.id)
                    );
                    
                    // Update last seen packets
                    lastSeenPackets = packets;
                    
                    // Process new packets
                    newPackets.forEach(packet => {
                        addPacketToList(packet);
                        visualizePacket(packet);
                        updateNetworkGraph(packet);
                    });
                })
                .catch(err => {
                    console.error('Error polling packets:', err);
                })
                .finally(() => {
                    // Poll again in 500ms
                    setTimeout(pollPackets, 500);
                });
        }
        
        // Fetch devices
        function loadDevices() {
            fetch('/api/devices')
                .then(response => response.json())
                .then(devices => {
                    deviceList.innerHTML = '';
                    
                    devices.forEach(device => {
                        const deviceEl = document.createElement('div');
                        deviceEl.className = 'device-item';
                        
                        deviceEl.innerHTML = `
                            <div class=""device-name"">
                                <div class=""device-status ${device.isActive ? 'active' : ''}""></div>
                                <span>${device.description || device.name}</span>
                            </div>
                            <button class=""btn ${device.isActive ? 'btn-danger' : 'btn-success'}"" 
                                    data-device=""${device.index}""
                                    data-action=""${device.isActive ? 'stop' : 'start'}"">
                                <i class=""fas fa-${device.isActive ? 'stop' : 'play'}""></i>
                            </button>
                        `;
                        
                        deviceList.appendChild(deviceEl);
                    });
                    
                    // Add event listeners to device buttons
                    document.querySelectorAll('.device-item .btn').forEach(btn => {
                        btn.addEventListener('click', handleDeviceAction);
                    });
                })
                .catch(err => {
                    console.error('Error loading devices:', err);
                    deviceList.innerHTML = `<div class=""text-danger"">Error loading devices</div>`;
                });
        }
        
        // Load IP addresses
        function loadIpAddresses() {
            fetch('/api/ipaddresses')
                .then(response => response.json())
                .then(data => {
                    const ipSelect = document.getElementById('ip-select');
                    const currentValue = ipSelect.value;
                    
                    // Clear options except the first one
                    while (ipSelect.options.length > 1) {
                        ipSelect.remove(1);
                    }
                    
                    // Add IP options
                    data.ActiveIps.forEach(ip => {
                        const option = document.createElement('option');
                        option.value = ip;
                        option.textContent = `${ip} (${data.IpStats[ip] || 0} packets)`;
                        ipSelect.appendChild(option);
                    });
                    
                    // Restore selected value if possible
                    if (currentValue && [...ipSelect.options].some(o => o.value === currentValue)) {
                        ipSelect.value = currentValue;
                    }
                    
                    // Show active filter if any
                    const activeFilterEl = document.getElementById('active-filter');
                    if (data.FilterActive && data.SelectedIp) {
                        activeFilterEl.innerHTML = `<div class=""active-filter"">Currently filtering: ${data.SelectedIp}</div>`;
                    } else {
                        activeFilterEl.innerHTML = '';
                    }
                })
                .catch(err => {
                    console.error('Error loading IP addresses:', err);
                });
        }
        
        // Add packet to list
        function addPacketToList(packet) {
            const packetEl = document.createElement('div');
            packetEl.className = 'packet-item';
            packetEl.dataset.id = packet.id;
            
            let protocolClass = packet.applicationProtocol?.toLowerCase() || packet.transportProtocol.toLowerCase();
            if (packet.isEncrypted && !packet.wasDecrypted) {
                protocolClass = 'encrypted';
            }
            
            packetEl.innerHTML = `
                <div class=""packet-info"">
                    <div class=""packet-protocol ${protocolClass}"">
                        ${packet.applicationProtocol || packet.transportProtocol}
                    </div>
                    <div>
                        <div>${packet.sourceIp}:${packet.sourcePort} → ${packet.destinationIp}:${packet.destinationPort}</div>
                        <div class=""packet-time"">${packet.time} - ${packet.length} bytes</div>
                    </div>
                </div>
                <div>
                    ${packet.isEncrypted ? 
                      (packet.wasDecrypted ? '<i class=""fas fa-unlock text-success""></i>' : '<i class=""fas fa-lock text-danger""></i>') : 
                      '<i class=""fas fa-file-alt""></i>'}
                </div>
            `;
            
            packetEl.addEventListener('click', () => showPacketDetails(packet));
            
            packetList.insertBefore(packetEl, packetList.firstChild);
            
            // Limit list size
            if (packetList.children.length > 100) {
                packetList.removeChild(packetList.lastChild);
            }
        }
        
        // Visualize packet in stream
        function visualizePacket(packet) {
            const packetEl = document.createElement('div');
            packetEl.className = `packet ${packet.isEncrypted ? (packet.wasDecrypted ? 'decrypted' : 'encrypted') : ''}`;
            
            // Random position on Y axis
            const yPos = Math.floor(Math.random() * (packetStream.offsetHeight - 20)) + 5;
            packetEl.style.top = `${yPos}px`;
            
            packetStream.appendChild(packetEl);
            
            // Remove after animation completes
            setTimeout(() => {
                if (packetEl.parentNode === packetStream) {
                    packetStream.removeChild(packetEl);
                }
            }, 3000);
        }
        
        // Show packet details modal
        function showPacketDetails(packet) {
            modalTitle.textContent = `Packet Details - ${packet.applicationProtocol || packet.transportProtocol}`;
            
            packetDetails.innerHTML = `
                <div class=""detail-group"">
                    <h3>General Information</h3>
                    <div class=""detail-item"">
                        <span class=""detail-label"">Time</span>
                        <span class=""detail-value"">${packet.time}</span>
                    </div>
                    <div class=""detail-item"">
                        <span class=""detail-label"">Length</span>
                        <span class=""detail-value"">${packet.length} bytes</span>
                    </div>
                    <div class=""detail-item"">
                        <span class=""detail-label"">Status</span>
                        <span class=""detail-value"">${packet.status}</span>
                    </div>
                    <div class=""detail-item"">
                        <span class=""detail-label"">Has Errors</span>
                        <span class=""detail-value ${packet.hasErrors ? 'text-danger' : 'text-success'}"">
                            ${packet.hasErrors ? 'Yes' : 'No'}
                        </span>
                    </div>
                </div>
                
                <div class=""detail-group"">
                    <h3>Protocol Information</h3>
                    <div class=""detail-item"">
                        <span class=""detail-label"">Transport Protocol</span>
                        <span class=""detail-value"">${packet.transportProtocol}</span>
                    </div>
                    <div class=""detail-item"">
                        <span class=""detail-label"">Application Protocol</span>
                        <span class=""detail-value"">${packet.applicationProtocol || 'Unknown'}</span>
                    </div>
                    <div class=""detail-item"">
                        <span class=""detail-label"">Encrypted</span>
                        <span class=""detail-value ${packet.isEncrypted ? 'text-danger' : 'text-success'}"">
                            ${packet.isEncrypted ? 'Yes' : 'No'}
                        </span>
                    </div>
                    ${packet.isEncrypted ? `
                    <div class=""detail-item"">
                        <span class=""detail-label"">Decrypted</span>
                        <span class=""detail-value ${packet.wasDecrypted ? 'text-success' : 'text-danger'}"">
                            ${packet.wasDecrypted ? 'Yes' : 'No'}
                        </span>
                    </div>
                    ` : ''}
                    ${packet.additionalInfo && packet.additionalInfo.ProtocolConfidence ? `
                    <div class=""detail-item"">
                        <span class=""detail-label"">Detection Confidence</span>
                        <span class=""detail-value"">${packet.additionalInfo.ProtocolConfidence}</span>
                    </div>
                    ` : ''}
                    ${packet.additionalInfo && packet.additionalInfo.IdentificationMethod ? `
                    <div class=""detail-item"">
                        <span class=""detail-label"">Detection Method</span>
                        <span class=""detail-value"">${packet.additionalInfo.IdentificationMethod}</span>
                    </div>
                    ` : ''}
                    ${packet.additionalInfo && packet.additionalInfo.EncryptionType ? `
                    <div class=""detail-item"">
                        <span class=""detail-label"">Encryption Type</span>
                        <span class=""detail-value"">${packet.additionalInfo.EncryptionType}</span>
                    </div>
                    ` : ''}
                </div>
                
                <div class=""detail-group"">
                    <h3>Connection Information</h3>
                    <div class=""detail-item"">
                        <span class=""detail-label"">Source</span>
                        <span class=""detail-value"">${packet.sourceIp}:${packet.sourcePort}</span>
                    </div>
                    <div class=""detail-item"">
                        <span class=""detail-label"">Destination</span>
                        <span class=""detail-value"">${packet.destinationIp}:${packet.destinationPort}</span>
                    </div>
                </div>
                
                <!-- Placeholder for payload data -->
                <div class=""packet-payload"">
                    Packet payload data would be displayed here in a production environment.
                    
                    For security and privacy reasons, actual packet content is not shown in this demo.
                    
                    In a full implementation, this would contain:
                    - Raw hex dump of packet content
                    - Decoded protocol-specific fields
                    - Decrypted content (if available)
                </div>
            `;
            
            packetModal.style.display = 'flex';
        }
        
        // Update statistics
        function updateStats(stats) {
            totalPacketsEl.textContent = stats.TotalPackets;
            encryptedPacketsEl.textContent = stats.EncryptedPackets;
            decryptedPacketsEl.textContent = stats.DecryptedPackets;
            errorPacketsEl.textContent = stats.TotalPackets - (stats.EncryptedPackets + stats.DecryptedPackets);
            
            // Update chart
            if (stats.ProtocolStats) {
                const data = [
                    stats.ProtocolStats.HTTP || 0,
                    stats.ProtocolStats.HTTPS || 0,
                    stats.ProtocolStats.DNS || 0,
                    stats.ProtocolStats.TCP || 0,
                    stats.ProtocolStats.UDP || 0,
                    stats.ProtocolStats.Other || 0
                ];
                
                protocolChart.data.datasets[0].data = data;
                protocolChart.update();
            }
        }
        
        // Network Graph Visualization
        function initNetworkGraph() {
            // Create central node (your computer)
            const centralNode = document.createElement('div');
            centralNode.className = 'network-node';
            centralNode.innerHTML = '<i class=""fas fa-laptop""></i>';
            centralNode.style.left = '50%';
            centralNode.style.top = '50%';
            centralNode.style.transform = 'translate(-50%, -50%)';
            
            networkGraph.appendChild(centralNode);
            
            // Store network nodes for later reference
            networkNodes.central = centralNode;
        }
        
        function updateNetworkGraph(packet) {
            const { sourceIp, destinationIp } = packet;
            
            // Process only unique IPs (limit to 10 nodes)
            const uniqueIp = sourceIp !== '127.0.0.1' && sourceIp !== 'localhost' ? 
                sourceIp : destinationIp;
            
            if (uniqueIp === '127.0.0.1' || uniqueIp === 'localhost') return;
            
            if (!networkNodes.remotes[uniqueIp] && Object.keys(networkNodes.remotes).length < 10) {
                // Create new node at random position around central node
                const angle = Math.random() * Math.PI * 2;
                const distance = 70; // Distance from center
                
                const x = 50 + Math.cos(angle) * distance;
                const y = 50 + Math.sin(angle) * distance;
                
                const nodeEl = document.createElement('div');
                nodeEl.className = 'network-node';
                nodeEl.innerHTML = '<i class=""fas fa-server""></i>';
                nodeEl.style.left = `${x}%`;
                nodeEl.style.top = `${y}%`;
                nodeEl.style.transform = 'translate(-50%, -50%)';
                
                // Create link to central node
                const linkEl = document.createElement('div');
                linkEl.className = 'network-link';
                linkEl.style.left = '50%';
                linkEl.style.top = '50%';
                
                // Calculate link width and rotation
                const width = Math.sqrt(Math.pow((x - 50), 2) + Math.pow((y - 50), 2));
                linkEl.style.width = `${width}%`;
                
                // Calculate angle for rotation
                const rotationAngle = Math.atan2(y - 50, x - 50) * 180 / Math.PI;
                linkEl.style.transform = `rotate(${rotationAngle}deg)`;
                
                networkGraph.appendChild(linkEl);
                networkGraph.appendChild(nodeEl);
                
                // Store references
                networkNodes.remotes[uniqueIp] = {
                    node: nodeEl,
                    link: linkEl,
                    x,
                    y
                };
            }
            
            // Animate packet flow if we have both nodes
            if (networkNodes.remotes[uniqueIp]) {
                const { x, y } = networkNodes.remotes[uniqueIp];
                
                // Create packet animation
                const packetEl = document.createElement('div');
                packetEl.className = 'network-packet';
                
                // Start position (central or remote depending on direction)
                const isOutgoing = destinationIp === uniqueIp;
                if (isOutgoing) {
                    packetEl.style.left = '50%';
                    packetEl.style.top = '50%';
                } else {
                    packetEl.style.left = `${x}%`;
                    packetEl.style.top = `${y}%`;
                }
                
                networkGraph.appendChild(packetEl);
                
                // Animate
                const startTime = Date.now();
                const duration = 1000; // 1 second
                
                function animatePacket() {
                    const elapsed = Date.now() - startTime;
                    const progress = Math.min(elapsed / duration, 1);
                    
                    if (isOutgoing) {
                        packetEl.style.left = `${50 + (x - 50) * progress}%`;
                        packetEl.style.top = `${50 + (y - 50) * progress}%`;
                    } else {
                        packetEl.style.left = `${x - (x - 50) * progress}%`;
                        packetEl.style.top = `${y - (y - 50) * progress}%`;
                    }
                    
                    if (progress < 1) {
                        requestAnimationFrame(animatePacket);
                    } else {
                        if (packetEl.parentNode === networkGraph) {
                            networkGraph.removeChild(packetEl);
                        }
                    }
                }
                
                requestAnimationFrame(animatePacket);
            }
        }
        
        // Event Handlers
        startBtn.addEventListener('click', () => {
            sendCommand('start');
        });
        
        stopBtn.addEventListener('click', () => {
            sendCommand('stop');
        });
        
        clearBtn.addEventListener('click', () => {
            sendCommand('clearstats');
            packetList.innerHTML = '';
        });
        
        // IP filter buttons
        document.getElementById('apply-filter-btn').addEventListener('click', () => {
            const ipAddress = document.getElementById('ip-select').value;
            if (ipAddress) {
                sendCommand('setipfilter', { ipAddress, enable: true });
            }
        });
        
        document.getElementById('clear-filter-btn').addEventListener('click', () => {
            sendCommand('setipfilter', { ipAddress: null, enable: false });
        });
        
        function handleDeviceAction(e) {
            const btn = e.currentTarget;
            const deviceIndex = btn.dataset.device;
            const action = btn.dataset.action;
            
            sendCommand(action, { deviceIndex: parseInt(deviceIndex) });
        }
        
        closeModal.addEventListener('click', () => {
            packetModal.style.display = 'none';
        });
        
        window.addEventListener('click', (e) => {
            if (e.target === packetModal) {
                packetModal.style.display = 'none';
            }
        });
        
        // Send command to server
        async function sendCommand(command, params = {}) {
            try {
                const response = await fetch('/api/command', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        command,
                        ...params
                    })
                });
                
                const result = await response.json();
                
                if (!result.success) {
                    console.error('Command error:', result.message);
                    // Could show error notification here
                }
                
                // Refresh devices after command
                if (command === 'start' || command === 'stop') {
                    setTimeout(loadDevices, 500);
                }
            } catch (err) {
                console.error('Error sending command:', err);
            }
        }
    </script>
</body>
</html>";
        }
    }

    // Command request/response models
    public class CommandRequest
    {
        public string Command { get; set; }
        public int? DeviceIndex { get; set; }
        public bool? Enable { get; set; }
        public string IpAddress { get; set; }
    }

    public class CommandResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
    }
}