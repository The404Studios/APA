using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace AdvancedPacketAnalyzer
{
    /// <summary>
    /// Enhanced protocol identification system to detect protocols based on 
    /// packet content, signatures, and port information with confidence scoring
    /// </summary>
    public class ProtocolIdentifier
    {
        // Dictionary of well-known ports to protocols
        private static readonly Dictionary<int, string> WellKnownPorts = new Dictionary<int, string>
        {
            // Web protocols
            { 80, "HTTP" },
            { 443, "HTTPS" },
            { 8080, "HTTP" },
            { 8443, "HTTPS" },
            { 3000, "HTTP" }, // Common development port
            
            // Email protocols
            { 25, "SMTP" },
            { 465, "SMTPS" },
            { 587, "SMTP" },
            { 110, "POP3" },
            { 995, "POP3S" },
            { 143, "IMAP" },
            { 993, "IMAPS" },
            
            // File transfer
            { 20, "FTP-Data" },
            { 21, "FTP" },
            { 22, "SSH/SFTP" },
            { 989, "FTPS-Data" },
            { 990, "FTPS" },
            
            // Name resolution
            { 53, "DNS" },
            { 5353, "mDNS" },
            { 5355, "LLMNR" },
            
            // Remote access
            { 22, "SSH" },
            { 23, "Telnet" },
            { 3389, "RDP" },
            { 5900, "VNC" },
            
            // Database
            { 1433, "MSSQL" },
            { 1521, "Oracle" },
            { 3306, "MySQL" },
            { 5432, "PostgreSQL" },
            { 6379, "Redis" },
            { 27017, "MongoDB" },
            
            // Messaging and real-time
            { 1883, "MQTT" },
            { 8883, "MQTT-TLS" },
            { 5222, "XMPP" },
            { 5223, "XMPP-TLS" },
            { 5060, "SIP" },
            { 5061, "SIPS" },
            { 5269, "XMPP-Server" },
            
            // Media streaming
            { 554, "RTSP" },
            { 1935, "RTMP" },
            { 8554, "RTSP" },
            
            // VPN/Tunneling
            { 1194, "OpenVPN" },
            { 1701, "L2TP" },
            { 1723, "PPTP" },
            { 4500, "IPsec" },
            { 500, "IKE" },
            { 51820, "WireGuard" },
            
            // Gaming
            { 27015, "Steam" },
            { 3724, "Blizzard" },
            
            // Others
            { 161, "SNMP" },
            { 162, "SNMP-Trap" },
            { 445, "SMB" },
            { 137, "NetBIOS-NS" },
            { 138, "NetBIOS-DGM" },
            { 139, "NetBIOS-SSN" },
            { 67, "DHCP-Server" },
            { 68, "DHCP-Client" },
            { 123, "NTP" },
            { 5672, "AMQP" },
            { 5671, "AMQPS" },
            { 6443, "Kubernetes" },
            { 2379, "etcd" },
        };

        // Protocol signature patterns
        private static readonly List<ProtocolSignature> ProtocolSignatures = new List<ProtocolSignature>
        {
            // HTTP signatures
            new ProtocolSignature
            {
                Protocol = "HTTP",
                Transport = "TCP",
                PatternType = PatternType.Regex,
                Pattern = @"^(GET|POST|HEAD|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH) .+ HTTP/\d\.\d\r\n",
                ConfidenceScore = 0.95f
            },
            new ProtocolSignature
            {
                Protocol = "HTTP",
                Transport = "TCP",
                PatternType = PatternType.Regex,
                Pattern = @"^HTTP/\d\.\d \d{3} .+\r\n",
                ConfidenceScore = 0.95f
            },
            
            // HTTPS/TLS signatures
            new ProtocolSignature
            {
                Protocol = "TLS",
                Transport = "TCP",
                PatternType = PatternType.Binary,
                BinaryPattern = new byte[] { 0x16, 0x03 }, // TLS Handshake + Version
                ConfidenceScore = 0.9f
            },
            new ProtocolSignature
            {
                Protocol = "TLS",
                Transport = "TCP",
                PatternType = PatternType.Binary,
                BinaryPattern = new byte[] { 0x17, 0x03 }, // TLS Application Data + Version
                ConfidenceScore = 0.9f
            },
            
            // DNS signatures
            new ProtocolSignature
            {
                Protocol = "DNS",
                Transport = "UDP",
                PatternType = PatternType.Binary,
                // Check for DNS header structure - simple check for standard query or response
                // 2 bytes ID + 2 bytes flags with specific bit patterns
                BinaryPatternMatcher = (data) =>
                {
                    if (data.Length < 12) return false; // DNS header is at least 12 bytes
                    // Check for typical query/response
                    // Second byte often 0x00 or 0x01 for query, other values for responses
                    byte secondByte = data[1];
                    // Check for DNS message structure - QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
                    return (secondByte <= 0x02);
                },
                ConfidenceScore = 0.8f
            },
            
            // SSH signatures
            new ProtocolSignature
            {
                Protocol = "SSH",
                Transport = "TCP",
                PatternType = PatternType.Regex,
                Pattern = @"^SSH-\d\.\d",
                ConfidenceScore = 0.95f
            },
            
            // SMTP signatures
            new ProtocolSignature
            {
                Protocol = "SMTP",
                Transport = "TCP",
                PatternType = PatternType.Regex,
                Pattern = @"^220 .+ SMTP",
                ConfidenceScore = 0.9f
            },
            new ProtocolSignature
            {
                Protocol = "SMTP",
                Transport = "TCP",
                PatternType = PatternType.Regex,
                Pattern = @"^(HELO|EHLO|MAIL FROM|RCPT TO|DATA|QUIT)",
                ConfidenceScore = 0.85f
            },
            
            // FTP signatures
            new ProtocolSignature
            {
                Protocol = "FTP",
                Transport = "TCP",
                PatternType = PatternType.Regex,
                Pattern = @"^220 .+ FTP",
                ConfidenceScore = 0.9f
            },
            new ProtocolSignature
            {
                Protocol = "FTP",
                Transport = "TCP",
                PatternType = PatternType.Regex,
                Pattern = @"^(USER|PASS|CWD|LIST|RETR|STOR|QUIT)",
                ConfidenceScore = 0.85f
            },
            
            // MQTT signatures
            new ProtocolSignature
            {
                Protocol = "MQTT",
                Transport = "TCP",
                PatternType = PatternType.Binary,
                BinaryPatternMatcher = (data) =>
                {
                    if (data.Length < 2) return false;
                    byte firstByte = data[0];
                    // MQTT packet type is in the high 4 bits of first byte
                    int packetType = (firstByte >> 4) & 0x0F;
                    // Check for valid MQTT packet types (1-14)
                    return packetType >= 1 && packetType <= 14;
                },
                ConfidenceScore = 0.85f
            },
            
            // RTP signatures (for VoIP, video streaming)
            new ProtocolSignature
            {
                Protocol = "RTP",
                Transport = "UDP",
                PatternType = PatternType.Binary,
                BinaryPatternMatcher = (data) =>
                {
                    if (data.Length < 12) return false; // RTP header is at least 12 bytes
                    // Check version (first 2 bits should be 10 - version 2)
                    return (data[0] & 0xC0) == 0x80;
                },
                ConfidenceScore = 0.8f
            },
            
            // WebSocket signatures
            new ProtocolSignature
            {
                Protocol = "WebSocket",
                Transport = "TCP",
                PatternType = PatternType.Binary,
                BinaryPatternMatcher = (data) =>
                {
                    if (data.Length < 2) return false;
                    byte firstByte = data[0];
                    byte secondByte = data[1];
                    
                    // FIN bit + reserved bits + valid opcode
                    bool validFirstByte = (firstByte & 0x70) == 0 && (firstByte & 0x0F) <= 0x0A;
                    // Mask bit should be set for client->server
                    bool hasMaskBit = (secondByte & 0x80) != 0;

                    return validFirstByte && hasMaskBit;
                },
                ConfidenceScore = 0.75f
            },
            
            // SIP signatures (VoIP)
            new ProtocolSignature
            {
                Protocol = "SIP",
                Transport = "UDP",
                PatternType = PatternType.Regex,
                Pattern = @"^(INVITE|REGISTER|OPTIONS|BYE|CANCEL|ACK|SUBSCRIBE|NOTIFY) .+ SIP/\d\.\d",
                ConfidenceScore = 0.9f
            },
            new ProtocolSignature
            {
                Protocol = "SIP",
                Transport = "UDP",
                PatternType = PatternType.Regex,
                Pattern = @"^SIP/\d\.\d \d{3} ",
                ConfidenceScore = 0.9f
            },
            
            // RTSP signatures
            new ProtocolSignature
            {
                Protocol = "RTSP",
                Transport = "TCP",
                PatternType = PatternType.Regex,
                Pattern = @"^(DESCRIBE|SETUP|PLAY|PAUSE|TEARDOWN|OPTIONS|ANNOUNCE|RECORD) .+ RTSP/\d\.\d",
                ConfidenceScore = 0.9f
            },
            new ProtocolSignature
            {
                Protocol = "RTSP",
                Transport = "TCP",
                PatternType = PatternType.Regex,
                Pattern = @"^RTSP/\d\.\d \d{3} ",
                ConfidenceScore = 0.9f
            },
            
            // BitTorrent signatures
            new ProtocolSignature
            {
                Protocol = "BitTorrent",
                Transport = "TCP",
                PatternType = PatternType.Binary,
                BinaryPattern = new byte[] { 0x13, 0x42, 0x69, 0x74, 0x54, 0x6F, 0x72, 0x72, 0x65, 0x6E, 0x74, 0x20, 0x70, 0x72, 0x6F, 0x74, 0x6F, 0x63, 0x6F, 0x6C },
                ConfidenceScore = 0.95f
            },
            
            // SMB signatures
            new ProtocolSignature
            {
                Protocol = "SMB",
                Transport = "TCP",
                PatternType = PatternType.Binary,
                BinaryPattern = new byte[] { 0xFF, 0x53, 0x4D, 0x42 }, // SMB1
                ConfidenceScore = 0.9f
            },
            new ProtocolSignature
            {
                Protocol = "SMB2",
                Transport = "TCP",
                PatternType = PatternType.Binary,
                BinaryPattern = new byte[] { 0xFE, 0x53, 0x4D, 0x42 }, // SMB2
                ConfidenceScore = 0.9f
            },
            
            // DHCP signatures
            new ProtocolSignature
            {
                Protocol = "DHCP",
                Transport = "UDP",
                PatternType = PatternType.Binary,
                BinaryPatternMatcher = (data) =>
                {
                    if (data.Length < 236) return false; // Minimum DHCP message size
                    return data[0] == 0x01 || data[0] == 0x02; // BOOTREQUEST or BOOTREPLY
                },
                ConfidenceScore = 0.85f
            },
            
            // QUIC signatures
            new ProtocolSignature
            {
                Protocol = "QUIC",
                Transport = "UDP",
                PatternType = PatternType.Binary,
                BinaryPatternMatcher = (data) =>
                {
                    if (data.Length < 4) return false;
                    // QUIC packets typically start with flags that include connection ID lengths
                    // This is a simplified check
                    byte firstByte = data[0];
                    return (firstByte & 0x80) != 0; // Long header format check
                },
                ConfidenceScore = 0.7f
            },
            
            // DoH (DNS over HTTPS) signatures
            new ProtocolSignature
            {
                Protocol = "DoH",
                Transport = "TCP",
                PatternType = PatternType.Regex,
                Pattern = @"^(GET|POST) /dns-query",
                ConfidenceScore = 0.85f
            },
            
            // gRPC signatures
            new ProtocolSignature
            {
                Protocol = "gRPC",
                Transport = "TCP",
                PatternType = PatternType.Binary,
                BinaryPatternMatcher = (data) =>
                {
                    if (data.Length < 9) return false;
                    // HTTP/2 frame header + gRPC specific patterns
                    return data[0] == 0x00 && data[3] == 0x01; // Length + HEADERS frame type
                },
                ConfidenceScore = 0.7f
            },
            
            // IMAP signatures
            new ProtocolSignature
            {
                Protocol = "IMAP",
                Transport = "TCP",
                PatternType = PatternType.Regex,
                Pattern = @"^\* OK .+IMAP",
                ConfidenceScore = 0.9f
            },
            new ProtocolSignature
            {
                Protocol = "IMAP",
                Transport = "TCP",
                PatternType = PatternType.Regex,
                Pattern = @"^[A-Z0-9]+ (LOGIN|SELECT|FETCH|STORE|LIST|LOGOUT)",
                ConfidenceScore = 0.8f
            },
            
            // POP3 signatures
            new ProtocolSignature
            {
                Protocol = "POP3",
                Transport = "TCP",
                PatternType = PatternType.Regex,
                Pattern = @"^\+OK",
                ConfidenceScore = 0.8f
            },
            new ProtocolSignature
            {
                Protocol = "POP3",
                Transport = "TCP",
                PatternType = PatternType.Regex,
                Pattern = @"^(USER|PASS|STAT|LIST|RETR|DELE|QUIT)",
                ConfidenceScore = 0.8f
            },
            
            // NTP signatures
            new ProtocolSignature
            {
                Protocol = "NTP",
                Transport = "UDP",
                PatternType = PatternType.Binary,
                BinaryPatternMatcher = (data) =>
                {
                    if (data.Length < 4) return false;
                    byte firstByte = data[0];
                    // NTP version in bits 3-5
                    int version = (firstByte >> 3) & 0x07;
                    // NTP mode in bits 0-2
                    int mode = firstByte & 0x07;
                    // Valid NTP versions are 1-4, valid modes are 1-7
                    return version >= 1 && version <= 4 && mode >= 1 && mode <= 7;
                },
                ConfidenceScore = 0.85f
            },
            
            // WireGuard signatures
            new ProtocolSignature
            {
                Protocol = "WireGuard",
                Transport = "UDP",
                PatternType = PatternType.Binary,
                BinaryPatternMatcher = (data) =>
                {
                    if (data.Length < 4) return false;
                    // WireGuard message types 1-4
                    return data[0] >= 1 && data[0] <= 4;
                },
                ConfidenceScore = 0.7f
            }
        };

        /// <summary>
        /// Identifies the protocol based on well-known ports, patterns, and heuristics
        /// </summary>
        /// <param name="packet">The packet to analyze</param>
        /// <returns>Protocol identification result with confidence score</returns>
        public static ProtocolIdentificationResult IdentifyProtocol(PacketContainer packet)
        {
            var result = new ProtocolIdentificationResult();

            // Create initial identification based on port
            IdentifyByPort(packet, result);

            // If payload data is available, analyze it for protocol signatures
            if (packet.PayloadData != null && packet.PayloadData.Length > 0)
            {
                IdentifyByPayload(packet, result);
            }

            // If protocol is still unknown, make an educated guess
            if (string.IsNullOrEmpty(result.IdentifiedProtocol) || result.ConfidenceScore < 0.4f)
            {
                MakeEstimatedGuess(packet, result);
            }

            // Default to transport protocol with low confidence if nothing else matches
            if (string.IsNullOrEmpty(result.IdentifiedProtocol))
            {
                result.IdentifiedProtocol = packet.TransportProtocol;
                result.ConfidenceScore = 0.3f;
                result.IdentificationMethod = "Default to Transport Protocol";
            }

            // Classify encryption
            DetermineEncryption(packet, result);

            return result;
        }

        /// <summary>
        /// Attempts to identify protocol based on well-known ports
        /// </summary>
        private static void IdentifyByPort(PacketContainer packet, ProtocolIdentificationResult result)
        {
            // Check destination port first (client to server)
            if (WellKnownPorts.TryGetValue(packet.DestinationPort, out string protocol))
            {
                result.IdentifiedProtocol = protocol;
                result.ConfidenceScore = 0.7f; // Port-based detection is fairly reliable but not perfect
                result.IdentificationMethod = "Standard Port";
                return;
            }

            // Also check source port (server to client)
            if (WellKnownPorts.TryGetValue(packet.SourcePort, out protocol))
            {
                result.IdentifiedProtocol = protocol;
                result.ConfidenceScore = 0.7f;
                result.IdentificationMethod = "Standard Port";
                return;
            }

            // Handle common non-standard ports
            if (packet.DestinationPort > 1024)
            {
                // HTTP often runs on high ports in dev environments
                if (packet.DestinationPort >= 8000 && packet.DestinationPort <= 8999)
                {
                    result.IdentifiedProtocol = "HTTP";
                    result.ConfidenceScore = 0.5f;
                    result.IdentificationMethod = "Common Non-Standard Port";
                    return;
                }

                // HTTP alternative ports
                if (packet.DestinationPort == 8080 || packet.DestinationPort == 8888)
                {
                    result.IdentifiedProtocol = "HTTP";
                    result.ConfidenceScore = 0.6f;
                    result.IdentificationMethod = "Common Non-Standard Port";
                    return;
                }

                // HTTPS alternative ports
                if (packet.DestinationPort == 8443 || packet.DestinationPort == 9443)
                {
                    result.IdentifiedProtocol = "HTTPS";
                    result.ConfidenceScore = 0.6f;
                    result.IdentificationMethod = "Common Non-Standard Port";
                    return;
                }
            }
        }

        /// <summary>
        /// Attempts to identify protocol by analyzing packet payload for known signatures
        /// </summary>
        private static void IdentifyByPayload(PacketContainer packet, ProtocolIdentificationResult result)
        {
            if (packet.PayloadData == null || packet.PayloadData.Length == 0)
                return;

            // Check for text-based protocol patterns first
            string textPayload = null;
            try
            {
                // Only convert the first N bytes to avoid large payloads
                int bytesToCheck = Math.Min(packet.PayloadData.Length, 128);
                textPayload = Encoding.ASCII.GetString(packet.PayloadData, 0, bytesToCheck);
            }
            catch
            {
                // If we can't convert to text, it's likely binary
                textPayload = null;
            }

            float bestScore = result.ConfidenceScore;

            // Match against signatures
            foreach (var signature in ProtocolSignatures)
            {
                // Skip if transport protocol doesn't match
                if (!string.IsNullOrEmpty(signature.Transport) &&
                    !signature.Transport.Equals(packet.TransportProtocol, StringComparison.OrdinalIgnoreCase))
                    continue;

                bool matched = false;

                switch (signature.PatternType)
                {
                    case PatternType.Regex:
                        if (!string.IsNullOrEmpty(textPayload))
                        {
                            matched = Regex.IsMatch(textPayload, signature.Pattern, RegexOptions.IgnoreCase);
                        }
                        break;

                    case PatternType.Binary:
                        if (signature.BinaryPattern != null)
                        {
                            matched = MatchesBinaryPattern(packet.PayloadData, signature.BinaryPattern);
                        }
                        else if (signature.BinaryPatternMatcher != null)
                        {
                            matched = signature.BinaryPatternMatcher(packet.PayloadData);
                        }
                        break;
                }

                if (matched && signature.ConfidenceScore > bestScore)
                {
                    result.IdentifiedProtocol = signature.Protocol;
                    result.ConfidenceScore = signature.ConfidenceScore;
                    result.IdentificationMethod = "Signature Match";
                    bestScore = signature.ConfidenceScore;
                }
            }
        }

        /// <summary>
        /// Makes an estimated guess for protocols that didn't match standard ports or signatures
        /// </summary>
        private static void MakeEstimatedGuess(PacketContainer packet, ProtocolIdentificationResult result)
        {
            // Look for characteristic patterns that might indicate protocol type

            // Check for potential encrypted traffic
            if (packet.PayloadData != null && packet.PayloadData.Length > 0)
            {
                // Check for high entropy in payload (common in encrypted traffic)
                if (HasHighEntropy(packet.PayloadData))
                {
                    if (packet.TransportProtocol == "TCP")
                    {
                        if (packet.DestinationPort == 443 || packet.SourcePort == 443)
                        {
                            result.IdentifiedProtocol = "HTTPS";
                            result.ConfidenceScore = 0.65f;
                        }
                        else
                        {
                            result.IdentifiedProtocol = "TLS";
                            result.ConfidenceScore = 0.5f;
                        }
                    }
                    else if (packet.TransportProtocol == "UDP")
                    {
                        result.IdentifiedProtocol = "DTLS"; // or could be other encrypted UDP
                        result.ConfidenceScore = 0.4f;
                    }

                    result.IdentificationMethod = "Entropy Analysis";
                    return;
                }

                // Check if it might be a binary protocol based on content
                if (IsProbablyBinaryProtocol(packet.PayloadData))
                {
                    if (packet.TransportProtocol == "TCP")
                    {
                        result.IdentifiedProtocol = "Binary Protocol";
                        result.ConfidenceScore = 0.4f;
                        result.IdentificationMethod = "Content Analysis";
                    }
                    else if (packet.TransportProtocol == "UDP")
                    {
                        // Many game protocols use UDP
                        if (packet.PayloadData.Length < 128)
                        {
                            result.IdentifiedProtocol = "Game Protocol";
                            result.ConfidenceScore = 0.4f;
                        }
                        else
                        {
                            result.IdentifiedProtocol = "Binary Protocol";
                            result.ConfidenceScore = 0.4f;
                        }
                        result.IdentificationMethod = "Content Analysis";
                    }
                    return;
                }

                // Check for characteristics of streaming media
                if (packet.TransportProtocol == "UDP" && packet.PayloadData.Length > 500)
                {
                    result.IdentifiedProtocol = "Streaming Media";
                    result.ConfidenceScore = 0.35f;
                    result.IdentificationMethod = "Size Analysis";
                    return;
                }
            }

            // Port ranges that might indicate specific protocols
            if (packet.DestinationPort >= 6881 && packet.DestinationPort <= 6889)
            {
                result.IdentifiedProtocol = "BitTorrent";
                result.ConfidenceScore = 0.5f;
                result.IdentificationMethod = "Port Range";
                return;
            }

            if (packet.DestinationPort >= 27000 && packet.DestinationPort <= 27050)
            {
                result.IdentifiedProtocol = "Game Traffic";
                result.ConfidenceScore = 0.4f;
                result.IdentificationMethod = "Port Range";
                return;
            }
        }

        /// <summary>
        /// Determines whether the packet is encrypted and tries to identify the encryption type
        /// </summary>
        private static void DetermineEncryption(PacketContainer packet, ProtocolIdentificationResult result)
        {
            // Some protocols are known to be encrypted
            if (result.IdentifiedProtocol == "HTTPS" ||
                result.IdentifiedProtocol == "TLS" ||
                result.IdentifiedProtocol == "DTLS" ||
                result.IdentifiedProtocol == "SSH" ||
                result.IdentifiedProtocol == "SMTPS" ||
                result.IdentifiedProtocol == "IMAPS" ||
                result.IdentifiedProtocol == "POP3S" ||
                result.IdentifiedProtocol == "FTPS" ||
                result.IdentifiedProtocol == "SFTP" ||
                result.IdentifiedProtocol == "SIPS" ||
                result.IdentifiedProtocol == "MQTT-TLS" ||
                result.IdentifiedProtocol == "WireGuard" ||
                result.IdentifiedProtocol == "OpenVPN")
            {
                packet.IsEncrypted = true;
                result.IsEncrypted = true;

                // Try to determine encryption algorithm if possible
                if (packet.PayloadData != null && packet.PayloadData.Length > 5)
                {
                    // Try to convert payload to text for text-based protocols like SSH
                    string textPayload = null;
                    try
                    {
                        int bytesToCheck = Math.Min(packet.PayloadData.Length, 64);
                        textPayload = Encoding.ASCII.GetString(packet.PayloadData, 0, bytesToCheck);
                    }
                    catch
                    {
                        // If conversion fails, leave as null
                    }

                    // TLS 1.2 detection
                    if (packet.PayloadData[0] == 0x16 && packet.PayloadData[1] == 0x03 && packet.PayloadData[2] == 0x03)
                    {
                        result.EncryptionType = "TLS 1.2";
                    }
                    // TLS 1.3 detection
                    else if (packet.PayloadData[0] == 0x16 && packet.PayloadData[1] == 0x03 && packet.PayloadData[2] == 0x04)
                    {
                        result.EncryptionType = "TLS 1.3";
                    }
                    // SSH detection
                    else if (result.IdentifiedProtocol == "SSH" && !string.IsNullOrEmpty(textPayload) &&
                             textPayload.StartsWith("SSH-"))
                    {
                        result.EncryptionType = "SSH Protocol";
                    }
                    else if (HasHighEntropy(packet.PayloadData))
                    {
                        result.EncryptionType = "Unknown Encryption";
                    }
                }
            }
            // Some protocols can be optionally encrypted
            else if (result.IdentifiedProtocol == "HTTP" ||
                     result.IdentifiedProtocol == "MQTT" ||
                     result.IdentifiedProtocol == "SMTP" ||
                     result.IdentifiedProtocol == "IMAP" ||
                     result.IdentifiedProtocol == "POP3" ||
                     result.IdentifiedProtocol == "FTP")
            {
                // Check if payload looks encrypted despite the protocol usually being cleartext
                if (packet.PayloadData != null && packet.PayloadData.Length > 0 && HasHighEntropy(packet.PayloadData))
                {
                    packet.IsEncrypted = true;
                    result.IsEncrypted = true;
                    result.EncryptionType = "Unexpected Encryption";
                    // Lower confidence since this is unusual
                    result.ConfidenceScore *= 0.8f;
                }
            }
        }

        /// <summary>
        /// Checks if a binary payload has the specified pattern at the beginning
        /// </summary>
        private static bool MatchesBinaryPattern(byte[] data, byte[] pattern)
        {
            if (data.Length < pattern.Length)
                return false;

            for (int i = 0; i < pattern.Length; i++)
            {
                if (data[i] != pattern[i])
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Determines if the data has high entropy, which often indicates encryption or compression
        /// </summary>
        private static bool HasHighEntropy(byte[] data)
        {
            if (data.Length < 20)
                return false;

            // Sample the data to reduce computation time
            int sampleSize = Math.Min(data.Length, 256);

            // Count byte frequencies
            int[] frequencies = new int[256];
            for (int i = 0; i < sampleSize; i++)
            {
                frequencies[data[i]]++;
            }

            // Calculate Shannon entropy
            double entropy = 0;
            for (int i = 0; i < 256; i++)
            {
                if (frequencies[i] > 0)
                {
                    double probability = (double)frequencies[i] / sampleSize;
                    entropy -= probability * Math.Log(probability, 2);
                }
            }

            // Normalized entropy value (max is 8 for byte values)
            // Values above 7.0 often indicate encryption or compression
            return entropy > 7.0;
        }

        /// <summary>
        /// Determines if the data is likely a binary protocol rather than text-based
        /// </summary>
        private static bool IsProbablyBinaryProtocol(byte[] data)
        {
            if (data.Length < 8)
                return false;

            // Check if significant portion of bytes are outside printable ASCII range
            int nonPrintableCount = 0;
            int sampleSize = Math.Min(data.Length, 64);

            for (int i = 0; i < sampleSize; i++)
            {
                byte b = data[i];
                if (b < 32 && b != 9 && b != 10 && b != 13) // Exclude tab, LF, CR
                {
                    nonPrintableCount++;
                }
                else if (b > 126)
                {
                    nonPrintableCount++;
                }
            }

            return (nonPrintableCount / (double)sampleSize) > 0.3; // 30% threshold
        }

        /// <summary>
        /// Apply protocol identification results to the packet
        /// </summary>
        /// <param name="packet">Packet to update</param>
        public static void ApplyProtocolIdentification(PacketContainer packet)
        {
            // Only process if application protocol is unknown
            if (string.IsNullOrEmpty(packet.ApplicationProtocol) ||
                packet.ApplicationProtocol == "UNKNOWN")
            {
                var result = IdentifyProtocol(packet);

                if (result.ConfidenceScore >= 0.4f)
                {
                    packet.ApplicationProtocol = result.IdentifiedProtocol;
                    packet.IsEncrypted = result.IsEncrypted;

                    // Record identification details for debugging/logging
                    packet.AdditionalInfo ??= new Dictionary<string, string>();
                    packet.AdditionalInfo["ProtocolConfidence"] = result.ConfidenceScore.ToString("0.00");
                    packet.AdditionalInfo["IdentificationMethod"] = result.IdentificationMethod;

                    if (!string.IsNullOrEmpty(result.EncryptionType))
                    {
                        packet.AdditionalInfo["EncryptionType"] = result.EncryptionType;
                    }
                }
            }
        }
    }

    /// <summary>
    /// Types of pattern matching for protocol signatures
    /// </summary>
    public enum PatternType
    {
        Regex,
        Binary
    }

    /// <summary>
    /// Protocol signature definition for identifying protocols from packet content
    /// </summary>
    public class ProtocolSignature
    {
        /// <summary>
        /// Protocol name
        /// </summary>
        public string Protocol { get; set; }

        /// <summary>
        /// Transport protocol (TCP/UDP) that this signature applies to
        /// </summary>
        public string Transport { get; set; }

        /// <summary>
        /// Type of pattern matching to use
        /// </summary>
        public PatternType PatternType { get; set; }

        /// <summary>
        /// Regex pattern for text-based protocol matching
        /// </summary>
        public string Pattern { get; set; }

        /// <summary>
        /// Binary pattern for matching at the start of payload
        /// </summary>
        public byte[] BinaryPattern { get; set; }

        /// <summary>
        /// Custom function for complex binary pattern matching
        /// </summary>
        public Func<byte[], bool> BinaryPatternMatcher { get; set; }

        /// <summary>
        /// Confidence score (0.0-1.0) indicating the reliability of this signature
        /// </summary>
        public float ConfidenceScore { get; set; }
    }

    /// <summary>
    /// Result of protocol identification
    /// </summary>
    public class ProtocolIdentificationResult
    {
        /// <summary>
        /// Identified protocol name
        /// </summary>
        public string IdentifiedProtocol { get; set; }

        /// <summary>
        /// Confidence score (0.0-1.0) indicating how likely the identification is correct
        /// </summary>
        public float ConfidenceScore { get; set; }

        /// <summary>
        /// Method used to identify the protocol
        /// </summary>
        public string IdentificationMethod { get; set; }

        /// <summary>
        /// Whether the protocol is encrypted
        /// </summary>
        public bool IsEncrypted { get; set; }

        /// <summary>
        /// Type of encryption if known
        /// </summary>
        public string EncryptionType { get; set; }
    }

    /// <summary>
    /// Extension to PacketContainer to support additional protocol information
    /// </summary>
    public static class PacketContainerExtensions
    {
        /// <summary>
        /// Apply advanced protocol identification to a packet
        /// </summary>
        public static void IdentifyProtocol(this PacketContainer packet)
        {
            ProtocolIdentifier.ApplyProtocolIdentification(packet);
        }
    }
}