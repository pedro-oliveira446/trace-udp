import socket
import struct
import time
import requests
from ip2geotools.databases.noncommercial import DbIpCity

def get_location(location_ip):
    formatted_address = '';
            
    if location_ip.city is not None:
        formatted_address += f" {location_ip.city},"
    if location_ip.region is not None:
        formatted_address += f" {location_ip.region},"
    if location_ip.country is not None:
        formatted_address += f" {location_ip.country},"

    if formatted_address != '':
        return formatted_address
    else:
        return None

def tracert(destino, max_hops=30, timeout=3):
    port = 33434  # Porta do Traceroute (UDP)

    for ttl in range(1, max_hops + 1):
        ssnd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        ssnd.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        ssnd.settimeout(timeout)

        srcv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        srcv.bind(('', port))
        srcv.settimeout(timeout)

        try:
            # Envia um pacote UDP para o destino
            ssnd.sendto(struct.pack('!HHHH', port, port, 8, 0)+ b'0', (destino, port))

            # Tenta receber uma resposta ICMP
            start_time = time.time()
            buffer, addr = srcv.recvfrom(1024)

            end_time = time.time()

            # Calcula o tempo de ida e volta
            rtt = (end_time - start_time) * 1000

            # Obtém o IP do roteador
            router_ip = addr[0]

            # Obtém as coordenadas geográficas associadas ao IP
            location_ip = DbIpCity.get(router_ip, api_key='free')

            location = "-"

            if location_ip is not None and location_ip.country != 'ZZ':

                # Obtém a localização a partir das coordenadas
                location = get_location(location_ip)

            
            # Obtém o nome do host associado ao IP
            try:
                router_host = socket.gethostbyaddr(router_ip)[0]

                router = f"{router_host} [{router_ip}]"
            except socket.herror:
                router = router_ip;

            print(f"{ttl}. (UDP) {router} {location} {rtt:.3f} ms")

            # Se atingiu o destino, sai do loop
            if router_ip == destino:
                break

        except socket.timeout:
            ssnd_icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            ssnd_icmp.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            ssnd_icmp.settimeout(timeout)

            try:
                # Construa um pacote ICMP Echo Request (ping)
                tipo = 8  # Echo Request
                codigo = 0
                checksum = 0
                identificador = 12345
                sequencia = 1
                dados = b'Hello!'
                pacote = struct.pack('!BBHHH', tipo, codigo, checksum, identificador, sequencia) + dados

                checksum = calcula_checksum(pacote)

                # Insere o checksum no pacote
                pacote = struct.pack('!BBHHH', tipo, codigo, checksum, identificador, sequencia) + dados

                # Envia o pacote ICMP Echo Request
                ssnd_icmp.sendto(pacote, (destino, 0))

                # Tenta receber uma resposta ICMP Echo Reply
                start_time = time.time()
                buffer, addr = ssnd_icmp.recvfrom(1024)
                end_time = time.time()

                # Calcula o tempo de ida e volta
                rtt = (end_time - start_time) * 1000

                # Obtém o IP do roteador
                router_ip = addr[0]

                # Obtém as coordenadas geográficas associadas ao IP
                location_ip = DbIpCity.get(router_ip, api_key='free')

                location = "-"

                if location_ip is not None and location_ip.country != 'ZZ':

                    # Obtém a localização a partir das coordenadas
                    location = get_location(location_ip)

                
                # Obtém o nome do host associado ao IP
                try:
                    router_host = socket.gethostbyaddr(router_ip)[0]

                    router = f"{router_host} [{router_ip}]"
                except socket.herror:
                    router = router_ip;

                print(f"{ttl}. (ICMP) {router} {location} {rtt:.3f} ms")

                # Se atingiu o destino, sai do loop
                if addr[0] == destino:
                    break
            except socket.timeout:
                print(f"{ttl}. *")
            except socket.error as e:
                print(f"Erro ICMP: {e}")
            finally:
                ssnd_icmp.close()

        except socket.error as e:
            print(f"Erro: {e}")
            break
        finally:
            ssnd.close()
            srcv.close()

def calcula_checksum(pacote):
    # Certifique-se de que o comprimento do pacote seja um número par
    if len(pacote) % 2 != 0:
        pacote += b'\x00'  # Adiciona um byte nulo se necessário

    # Calcula o checksum
    checksum = sum(struct.unpack('!H', pacote[i:i+2])[0] for i in range(0, len(pacote), 2))
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = ~checksum & 0xFFFF

    return checksum

if __name__ == "__main__":
    destino = input("Digite o endereço IP de destino: ")
    tracert(destino)
