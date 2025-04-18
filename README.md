![image](https://github.com/user-attachments/assets/4ec25da0-e3ec-4c77-bf99-a7bf9c6fa69e)
![image](https://github.com/user-attachments/assets/cb89c585-efd5-4b97-9907-91e4d85774f8) 



Advanced Network Packet Analyzer, Decryptor, and Manipulator v1.6.1 for windows 10/11


(WIP)

Captures packets
Decrypts the packets
Deserializes the packets
Puts them in a transport buffer
(figures out the keys) (wip)
Takes apart the packets and logs them to a file
(pushes/sockets? them back into original register transport) (wip)
Reserializes the packets
Forwards them to their destination


user‑mode TCP/UDP proxy. Intercept connections, handle decrypt/encrypt in code you control, parse and log streams.

Once the proxy approach is solid, profile where you need true packet‑level magic (e.g. ICMP, non‑IP protocols, or hardened games).

If you absolutely need raw‑packets, layer on a packet injector (WinDivert, npcap) but keep all the state logic inside your proxy core.

That way you get 90% of your functionality with 10% of the headache—and can still drop down to packet‑injection for the last mile?
