######################################################################################################################################################################
#LIBS
import socket
from concurrent.futures import ThreadPoolExecutor
from socket import AF_INET
from socket import SOCK_STREAM
from tqdm import tqdm
from scapy.all import *
import re
from art import *
#CONFIGS
conf.use_pcap = False #Desativa o aviso do pcap!
conf.sniff_promisc = False
conf.sniff_promisc = False
######################################################################################################################################################################
#Funções

######################################################################################################################################################################
# Função para verificar se a porta está aberta TCP
def scan_tcp_port(ip, port):                            
    with socket.socket(AF_INET, SOCK_STREAM) as sock:   # Cria um socket TCP com nome de sock
                                                        # AF_INET é o endereço IP e SOCK_STREAM é o protocolo TCP

        sock.settimeout(60)                              # Define o tempo limite para 1 segundo
        try:
            sock.connect((ip, port))                    # Tenta conectar ao IP e porta
            return port, True                           # Retorna a porta e True se a conexão for bem sucedida
        except:
            return port, False                          # Retorna a porta e False se a conexão falhar
######################################################################################################################################################################
# Função para verificar se a porta está aberta UDP
def scan_udp_port(ip, port):                                    
    with socket.socket(AF_INET, socket.SOCK_DGRAM) as sock:     # Cria um socket UDP com nome de sock 
                                                                # AF_INET é o endereço IP e SOCK_DGRAM é o protocolo UDP
                                                                
        sock.settimeout(90)                                      # Define o tempo limite para 1 segundo
        try:
            sock.sendto(b'', (ip, port))                        # Tenta enviar um pacote vazio para o IP e porta
            sock.recvfrom(1024)                                 # Tenta receber um pacote de 1024 bytes
            return port, True                                         # Retorna True se a conexão for bem sucedida
        except:
            return port, False                                        # Retorna False se a conexão falhar
######################################################################################################################################################################
# Função para verificar se a porta está aberta TCP ou UDP
def port_scan(ip, port, protocol='tcp'):                                
    print(f"\nScanning {ip} for {protocol.upper()} ports...")          # Imprime a mensagem de scan
    print("This process may take a while, please be patient...\n")      # Imprime a mensagem de espera
    print("To stop the scan press Ctrl+C\n")                            # Imprime a mensagem de interrupção


    if protocol == 'tcp':                                               # Se o protocolo for TCP
        test_function = scan_tcp_port                                   # A função de teste é scan_tcp_port
    elif protocol == 'udp':                                             # Se o protocolo for UDP
        test_function = scan_udp_port                                   # A função de teste é scan_udp_port        
    else:
        print("Invalid protocol")                                       # Se o protocolo for inválido, imprime a mensagem de erro
        return

    with ThreadPoolExecutor(max_workers=10) as executor:                                                                    # Cria um ThreadPoolExecutor com 10 workers
        results =  []                                                                                                       # Cria uma lista vazia para os resultados
        for result in tqdm(executor.map(test_function, [ip]*len(ports), ports), total=len(ports), desc="Scanning Ports"):   
                                                                                                                            # Para cada resultado em executor.map
                                                                                                                            # Mapeia a função de teste para o IP e portas [ip]*len(ports) significa 
            results.append(result)                                                                                          # que o IP será repetido para cada porta e ports é a lista de portas
                                                                                                                            # basicamente um for loop que executa a função de teste para cada porta mas
                                                                                                                            # na biblioteca concurrent.futures

    open_ports = [port for port, isopen in results if isopen]   # Exemplo results = [(22, True), (80, False), (443, True)]
    # Aqui, estamos a iterar sobre uma lista chamada results, que deve conter tuplas. Cada tupla tem dois elementos:
    #port: o número da porta.
    #isopen: um valor booleano (True ou False), que indica se a porta está aberta (True) ou fechada (False).

    
    if open_ports:
        print("Detecting OS...")
        for port in open_ports:
            banner = detect_os(ip, port)
            print("#######################################################")
            print(f"Port {port} is open!") # Imprime a porta aberta
            print(f"OS/Service: {banner}")
            print("#######################################################")
    else: 
        print("\nNo open ports found!") 
######################################################################################################################################################################
#Recebe a resposta completa em blocos até o servidor parar de enviar.
def receive_full_response(s):
    
    response = b""
    try:
        while True:
            chunk = s.recv(4096)  # Tamanho maior para capturar mais dados
            if not chunk:
                break
            response += chunk
    except socket.timeout:
        pass  
    return response.decode(errors="ignore").strip()
######################################################################################################################################################################
#Função para receber o OS / Serviço
def detect_os(ip, port):
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, port))

        if port in [80, 8080, 443]:  # Para HTTP/HTTPS, enviamos um pedido GET
            request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            s.send(request.encode())
            response = receive_full_response(s)  # Receber toda a resposta

            # Extrair apenas o cabeçalho "Server"
            match = re.search(r"(?i)^Server:\s*(.+)$", response, re.MULTILINE)
            banner = match.group(1) if match else "No server header detected."

        else:  # Para outras portas, tentamos receber um banner padrão
            banner = s.recv(4096).decode(errors="ignore").strip()

        s.close()
        return banner if banner else "No OS detected."
    except Exception:
        return "No response..."
######################################################################################################################################################################
#Main
if __name__ == "__main__":
    print("####################################################################################\n")
    tprint("PORT    SCANNER")
    print("ver 2.1 by W0lf13                                             Ethical Hacking Only!!")
    print("####################################################################################\n")
    try:
        # Solicitar o intervalo de portas primeiro
        print("PORT RANGE\n")
        lower_end = int(input("Lower end of the port range: "))
        higher_end = int(input("Higher end of the port range: "))

        if lower_end > higher_end:
            print("\nError: The lower end can't be higher than the higher end.")
        else:
            # Criar o intervalo de portas
            ports = list(range(lower_end, higher_end + 1))  
            print(f"\nRange of ports selected for scanning: [{lower_end} - {higher_end}")  # Exibir intervalo de portas

            # Solicitar o IP depois
            ip = input("\nEnter the IP address: ")

            # Confirmação antes de iniciar o scan
            start_scan = input("\nDo you want to start scanning? (y/n): ").lower()
            if start_scan == 'y':
                try:
                    # Iniciar o scan das portas
                    port_scan(ip, ports, protocol='tcp')
                    #port_scan(ip, ports, protocol='udp')  # Descomente para ativar o scan UDP
                except KeyboardInterrupt:
                    print("\nScan stopped by user!!\n")
            else:
                print("\nScan aborted.")
    except ValueError:
        print("Insert valid integers for port range!")
######################################################################################################################################################################