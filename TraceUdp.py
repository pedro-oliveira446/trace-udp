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

            print(f"{ttl}. {router} {location} {rtt:.3f} ms")

            # Se atingiu o destino, sai do loop
            if router_ip == destino:
                break

        except socket.timeout:
            print(f"{ttl}. *")
        except socket.error as e:
            print(f"Erro: {e}")
            break
        finally:
            ssnd.close()
            srcv.close()

if __name__ == "__main__":
    destino = input("Digite o endereço IP de destino: ")
    tracert(destino)
