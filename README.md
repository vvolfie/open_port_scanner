# open_port_scanner
Este script foi desenvolvido de forma a ajudar-me a promover o meu conhecimento sobre TCP e UDP, os ports e os seus serviços.

Este script apenas realiza uma auditoria ao target (host), revela se tiver alguma porta aberta e o seu serviço associado.

⚠️ATENÇÃO! NÃO USAR ESTE SCRIPT EM HOSTS NÃO AUTORIZADOS!!! USEM scanme.nmap.org PARA TESTAR! OU EM LABORATÓRIOS CRIADOS PARA TAL.

ETHICAL HACKING ONLY!

TCP - Utiliza o 3-Way Handshake (SYN - SYNACK - ACK)

UDP - Envia um pacote vazio e espera uma resposta:

Se a resposta for ICMP Type 3, Code 3 → Porta está fechada.

Se não houver resposta → Porta pode estar aberta ou filtrada.

Se houver resposta UDP → Porta está aberta e o serviço respondeu.


#######################################################################################
This script was developed to help me enhance my knowledge of TCP and UDP, ports, and their associated services.

This script only performs an audit on the target (host), revealing any open ports and their associated services.

⚠️ WARNING! DO NOT USE THIS SCRIPT ON UNAUTHORIZED HOSTS!!! Use scanme.nmap.org FOR TESTING OR DEDICATED LAB ENVIROMENTS!!

ETHICAL HACKING ONLY!

TCP
Uses the 3-Way Handshake (SYN → SYN-ACK → ACK)

UDP
Sends an empty packet and waits for a response:

If the response is ICMP Type 3, Code 3 → Port is closed.

If there is no response → Port may be open or filtered.

If there is a UDP response → Port is open and the service responded.

#######################################################################################
# Screenshots

![{C249498E-E256-4FE4-B7F8-6C18CC0CF610}](https://github.com/user-attachments/assets/831f680e-b94b-475f-ac39-b604beda7a43)
![{1292D96D-CEC8-47F5-9403-46F492BAAF61}](https://github.com/user-attachments/assets/ed645980-8e56-4a1c-ba33-d2e6fecbf6d8)
![{956C4520-616C-45CD-B2A5-0CB2451F2A94}](https://github.com/user-attachments/assets/9be0ea29-6273-4bb3-800d-65baffe0374f)


