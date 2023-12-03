import socket
import struct
import time
import requests

def get_location_from_coordinates(latitude, longitude):
    
    if latitude == 0 and longitude == 0:
        return "-"

    base_url = "https://nominatim.openstreetmap.org/reverse"
    params = {
        'format': 'json',
        'lat': latitude,
        'lon': longitude,
    }

    try:
        response = requests.get(base_url, params=params)
        data = response.json()

        formatted_address = '';
        
        if 'address' in data:
            if 'road' in data['address']:
                formatted_address += f" {data['address']['road']},"
            if 'city' in data['address']:
                formatted_address += f" {data['address']['city']},"
            if 'state' in data['address']:
                formatted_address += f" {data['address']['state']},"
            if 'country_code' in data['address']:
                formatted_address += f" {data['address']['country_code'].upper()},"

        if formatted_address == '' and 'display_name' in data:
            formatted_address = data['display_name']

        if formatted_address != '':
            return formatted_address
        else:
            return None
    except requests.exceptions.RequestException as e:
        print(f"Erro na solicitação da API: {e}")
        return None

def get_coordinates(ip_address):
    api_key = 'bc5123dd571bd4e41ef85b66416174ca'
    api_url = f'http://api.ipstack.com/{ip_address}?access_key={api_key}'

    try:
        response = requests.get(api_url)
        data = response.json()

        if 'latitude' in data and 'longitude' in data:
            return data['latitude'], data['longitude']
        else:
            return None
    except requests.exceptions.RequestException as e:
        print(f"Erro na solicitação da API: {e}")
        return None

def tracert(destino, max_hops=30, timeout=6):
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
            coordinates = get_coordinates(router_ip)

            location = "-"

            if coordinates is not None:

                # Obtém a localização a partir das coordenadas
                location = get_location_from_coordinates(coordinates[0],coordinates[1])

            
            
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
