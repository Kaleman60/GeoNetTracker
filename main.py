#!/usr/bin/env python3
"""
GeoNetTracker - Herramienta de geolocalización de tráfico de red

Este script captura tráfico de red saliente, extrae IPs únicas,
las geolocaliza y genera un mapa interactivo con Folium.
"""

import os
import sys
import subprocess
import time
from collections import defaultdict

import scapy
from scapy.all import sniff, IP, TCP, UDP
import folium
from folium.plugins import HeatMap
import requests


# ============================================================
# CONFIGURACIÓN - Ajusta estas coordenadas a tu ubicación
# ============================================================
MY_LAT = 40.416775   # Latitud de tu ubicación (ej: Madrid)
MY_LON = -3.703790   # Longitud de tu ubicación (ej: Madrid)

# Configuración de captura
CAPTURE_DURATION = 60  # Duración de captura en segundos
PACKET_COUNT = 1000    # Número máximo de paquetes a capturar

# URL de la API de geolocalización (gratuita) - en español
GEO_API_URL = "http://ip-api.com/json/?lang=es"

# Colores para servicios/puertos
SERVICE_COLORS = {
    443: {'color': 'green', 'name': 'HTTPS', 'icon': 'lock'},
    80: {'color': 'lightgreen', 'name': 'HTTP', 'icon': 'globe'},
    22: {'color': 'orange', 'name': 'SSH', 'icon': 'terminal'},
    21: {'color': 'purple', 'name': 'FTP', 'icon': 'folder'},
    25: {'color': 'darkred', 'name': 'SMTP', 'icon': 'envelope'},
    53: {'color': 'cadetblue', 'name': 'DNS', 'icon': 'book'},
    3306: {'color': 'pink', 'name': 'MySQL', 'icon': 'database'},
    5432: {'color': 'lightblue', 'name': 'PostgreSQL', 'icon': 'database'},
    27017: {'color': 'gray', 'name': 'MongoDB', 'icon': 'database'},
    3389: {'color': 'red', 'name': 'RDP', 'icon': 'desktop'},
}

DEFAULT_SERVICE = {'color': 'blue', 'name': 'Otro', 'icon': 'network-wired'}

# ============================================================
# DETECCIÓN DE TRÁFICO MALICIOSO
# ============================================================

# Puertos comúnmente usados por malware
MALICIOUS_PORTS = {
    4444: {'name': 'Metasploit', 'risk': 'HIGH'},
    5555: {'name': 'Android ADB/DroidJack', 'risk': 'HIGH'},
    8080: {'name': 'Proxy HTTP/Tomcat', 'risk': 'MEDIUM'},
    3128: {'name': 'Proxy Squid', 'risk': 'MEDIUM'},
    1337: {'name': 'Leet Port (Common)', 'risk': 'LOW'},
    31337: {'name': 'Back Orifice', 'risk': 'HIGH'},
    12345: {'name': 'NetBus', 'risk': 'HIGH'},
    27374: {'name': 'SubSeven', 'risk': 'HIGH'},
    1234: {'name': 'Kuang2/Virus', 'risk': 'HIGH'},
    9001: {'name': 'Tor ORPort', 'risk': 'MEDIUM'},
    9050: {'name': 'Tor SOCKS', 'risk': 'MEDIUM'},
    6667: {'name': 'IRC (Common Bot)', 'risk': 'MEDIUM'},
    6891: {'name': 'P2P/ZeuS', 'risk': 'HIGH'},
    6892: {'name': 'P2P/ZeuS', 'risk': 'HIGH'},
    6893: {'name': 'P2P/ZeuS', 'risk': 'HIGH'},
    6894: {'name': 'P2P/ZeuS', 'risk': 'HIGH'},
    6895: {'name': 'P2P/ZeuS', 'risk': 'HIGH'},
    6896: {'name': 'P2P/ZeuS', 'risk': 'HIGH'},
    6897: {'name': 'P2P/ZeuS', 'risk': 'HIGH'},
    6898: {'name': 'P2P/ZeuS', 'risk': 'HIGH'},
    6899: {'name': 'P2P/ZeuS', 'risk': 'HIGH'},
    6900: {'name': 'P2P/ZeuS', 'risk': 'HIGH'},
    6901: {'name': 'P2P/ZeuS', 'risk': 'HIGH'},
}

# Países de alto riesgo
HIGH_RISK_COUNTRIES = {
    'CN',  # China
    'RU',  # Russia
    'KP',  # North Korea
    'IR',  # Iran
    'SY',  # Syria
    'CU',  # Cuba
    'VN',  # Vietnam
    'BY',  # Belarus
    'MM',  # Myanmar
    'VE',  # Venezuela
}

# Puertos sensibles que requieren atención
SENSITIVE_PORTS = {
    22: 'SSH',
    23: 'Telnet',
    3389: 'RDP',
    5900: 'VNC',
    445: 'SMB',
    139: 'NetBIOS',
    135: 'RPC',
    1433: 'MSSQL',
    3306: 'MySQL',
    5432: 'PostgreSQL',
    27017: 'MongoDB',
    6379: 'Redis',
    9200: 'Elasticsearch',
}


# ============================================================
# CLASE PARA GESTIONAR CONEXIONES
# ============================================================
class NetworkTracker:
    """Clase principal para rastrear conexiones de red."""

    def __init__(self):
        # Almacena IPs únicas encontradas
        self.ips_found = set()
        # Almacena conexiones por IP
        self.connections = defaultdict(int)
        # Almacena puertos y protocolos por IP {ip: {port: protocol}}
        self.ports_by_ip = defaultdict(lambda: defaultdict(set))

    def process_packet(self, packet):
        """
        Procesa cada paquete capturado.
        Detecta IP, puerto y protocolo.

        Args:
            packet: Paquete Scapy capturado
        """
        # Verificar que el paquete tiene capa IP
        if IP in packet:
            # Obtener IP de origen y destino
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Determinar protocolo y puerto
            protocol = 'OTHER'
            src_port = None
            dst_port = None

            if TCP in packet:
                protocol = 'TCP'
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                protocol = 'UDP'
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

            # Ignorar IPs privadas/reservadas
            if not self._is_private_ip(src_ip):
                self.ips_found.add(src_ip)
                self.connections[src_ip] += 1
                if dst_port:
                    self.ports_by_ip[src_ip][dst_port].add(protocol)

            if not self._is_private_ip(dst_ip):
                self.ips_found.add(dst_ip)
                self.connections[dst_ip] += 1
                if dst_port:
                    self.ports_by_ip[dst_ip][dst_port].add(protocol)

    def _is_private_ip(self, ip):
        """
        Verifica si una IP es privada o reservada.

        Args:
            ip: Dirección IP a verificar

        Returns:
            bool: True si es IP privada/reservada
        """
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return True

            first = int(parts[0])
            second = int(parts[1])

            # IPs privadas RFC 1918
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True

            # Localhost
            if first == 127:
                return True

            # IPs reservadas/multicast
            if first >= 224:
                return True

        except (ValueError, IndexError):
            return True

        return False

    def _analyze_threats(self, ip, geo_data_item=None):
        """
        Analiza si una IP representa una amenaza potencial.

        Args:
            ip: Dirección IP a analizar
            geo_data_item: Datos de geolocalización (opcional)

        Returns:
            dict: Información de amenazas encontradas
        """
        threats = []
        risk_level = 'LOW'
        ports = self.ports_by_ip.get(ip, {})

        # Verificar puertos maliciosos conocidos
        for port in ports:
            if port in MALICIOUS_PORTS:
                threat = MALICIOUS_PORTS[port]
                threats.append({
                    'type': 'MALICIOUS_PORT',
                    'port': port,
                    'name': threat['name'],
                    'risk': threat['risk'],
                    'description': f"Puerto {port} asociado con {threat['name']}"
                })

        # Verificar puertos sensibles
        for port in ports:
            if port in SENSITIVE_PORTS:
                threats.append({
                    'type': 'SENSITIVE_PORT',
                    'port': port,
                    'name': SENSITIVE_PORTS[port],
                    'risk': 'MEDIUM',
                    'description': f"Conexión a puerto sensible: {SENSITIVE_PORTS[port]} ({port})"
                })

        # Verificar país de alto riesgo
        if geo_data_item and geo_data_item.get('country_code') in HIGH_RISK_COUNTRIES:
            threats.append({
                'type': 'HIGH_RISK_COUNTRY',
                'country': geo_data_item.get('country'),
                'country_code': geo_data_item.get('country_code'),
                'risk': 'HIGH',
                'description': f"Conexión a país de alto riesgo: {geo_data_item.get('country')}"
            })

        # Determinar nivel de riesgo overall
        if any(t['risk'] == 'HIGH' for t in threats):
            risk_level = 'HIGH'
        elif any(t['risk'] == 'MEDIUM' for t in threats):
            risk_level = 'MEDIUM'

        return {
            'threats': threats,
            'risk_level': risk_level,
            'is_suspicious': len(threats) > 0
        }

    def analyze_all_threats(self, geo_data):
        """
        Analiza todas las IPs para detectar amenazas.

        Args:
            geo_data: Lista de datos geolocalizados

        Returns:
            dict: Análisis completo de amenazas
        """
        threat_summary = {
            'total_ips': len(geo_data),
            'suspicious_ips': 0,
            'high_risk': 0,
            'medium_risk': 0,
            'low_risk': 0,
            'threat_details': []
        }

        # Crear diccionario deolocalización por IP ge
        geo_by_ip = {d['ip']: d for d in geo_data if d}

        for ip in self.ips_found:
            geo_item = geo_by_ip.get(ip)
            threat_analysis = self._analyze_threats(ip, geo_item)

            if threat_analysis['is_suspicious']:
                threat_summary['suspicious_ips'] += 1
                threat_summary['threat_details'].append({
                    'ip': ip,
                    'risk_level': threat_analysis['risk_level'],
                    'threats': threat_analysis['threats']
                })

                if threat_analysis['risk_level'] == 'HIGH':
                    threat_summary['high_risk'] += 1
                elif threat_analysis['risk_level'] == 'MEDIUM':
                    threat_summary['medium_risk'] += 1
                else:
                    threat_summary['low_risk'] += 1

        return threat_summary

    def _get_service_info(self, ip):
        """
        Obtiene información de servicios/puertos para una IP.

        Args:
            ip: Dirección IP

        Returns:
            dict: Información del servicio más relevante
        """
        if ip not in self.ports_by_ip:
            return DEFAULT_SERVICE.copy()

        ports = self.ports_by_ip[ip]
        for port in ports:
            if port in SERVICE_COLORS:
                service = SERVICE_COLORS[port].copy()
                service['port'] = port
                return service

        # Si no hay puertos conocidos
        for port in ports:
            service = DEFAULT_SERVICE.copy()
            service['port'] = port
            return service

        return DEFAULT_SERVICE.copy()

    def get_geolocation(self, ip):
        """
        Obtiene la geolocalización de una IP usando la API.
        Incluye información del propietario/ISP de la IP.

        Args:
            ip: Dirección IP a geolocalizar

        Returns:
            dict: Información de geolocalización o None si falla
        """
        try:
            response = requests.get(f"{GEO_API_URL}{ip}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'ip': ip,
                        'country': data.get('country', 'Unknown'),
                        'country_code': data.get('countryCode', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'region': data.get('regionName', 'Unknown'),
                        'lat': data.get('lat'),
                        'lon': data.get('lon'),
                        'isp': data.get('isp', 'Unknown'),
                        'asn': data.get('as', 'Unknown'),
                        'org': data.get('org', 'Unknown'),
                        'timezone': data.get('timezone', 'Unknown')
                    }
        except requests.RequestException as e:
            print(f"Error consultando IP {ip}: {e}")

        return None

    def create_map(self, geo_data):
        """
        Crea un mapa interactivo con las conexiones.
        Colorea las líneas según el servicio/puerto.
        Incluye capa de calor de intensidad.

        Args:
            geo_data: Lista de información geolocalizada de IPs

        Returns:
            folium.Map: Objeto mapa de Folium
        """
        # Crear mapa centrado en tu ubicación
        m = folium.Map(
            location=[MY_LAT, MY_LON],
            zoom_start=3,
            tiles='OpenStreetMap'
        )

        # Preparar datos para el mapa de calor
        heat_data = []
        # Contador de conexiones por ubicación
        location_counts = defaultdict(int)

        for data in geo_data:
            if data and data['lat'] and data['lon']:
                # Acumular peso por ubicación
                key = (data['lat'], data['lon'])
                location_counts[key] += 1

        # Crear lista para heatmap con peso
        for (lat, lon), count in location_counts.items():
            heat_data.append([lat, lon, count])

        # Agregar capa de calor si hay datos
        if heat_data:
            max_count = max([c for _, _, c in heat_data]) if heat_data else 1
            heat_layer = HeatMap(
                heat_data,
                min_opacity=0.4,
                max_val=max_count,
                radius=25,
                blur=15,
                gradient={0.2: 'blue', 0.4: 'lime', 0.6: 'yellow', 0.8: 'orange', 1: 'red'}
            )
            heat_layer.add_to(m)

        # Leyenda de colores y mapa de calor
        legend_html = '''
        <div style="position: fixed; bottom: 50px; left: 50px; z-index: 1000; 
                    background-color: white; padding: 10px; border: 2px solid gray;
                    border-radius: 5px; font-size: 12px;">
            <b>Leyenda de Servicios</b><br>
            <i class="fa fa-lock" style="color:green"></i> HTTPS (443)<br>
            <i class="fa fa-globe" style="color:lightgreen"></i> HTTP (80)<br>
            <i class="fa fa-terminal" style="color:orange"></i> SSH (22)<br>
            <i class="fa fa-folder" style="color:purple"></i> FTP (21)<br>
            <i class="fa fa-envelope" style="color:darkred"></i> SMTP (25)<br>
            <i class="fa fa-book" style="color:cadetblue"></i> DNS (53)<br>
            <i class="fa fa-database" style="color:pink"></i> MySQL (3306)<br>
            <i class="fa fa-database" style="color:lightblue"></i> PostgreSQL (5432)<br>
            <i class="fa fa-desktop" style="color:red"></i> RDP (3389)<br>
            <i class="fa fa-network-wired" style="color:blue"></i> Otro<br>
            <hr>
            <b>Mapa de Calor</b><br>
            <span style="color:red">●</span> Alta intensidad<br>
            <span style="color:orange">●</span> Media-alta<br>
            <span style="color:yellow">●</span> Media<br>
            <span style="color:lime">●</span> Baja<br>
            <span style="color:blue">●</span> Muy baja
        </div>
        '''
        m.get_root().html.add_child(folium.Element(legend_html))

        # Agregar marcador para tu ubicación
        folium.Marker(
            location=[MY_LAT, MY_LON],
            popup=f"<b>Tu Ubicación</b><br>Lat: {MY_LAT}<br>Lon: {MY_LON}",
            icon=folium.Icon(color='red', icon='home', prefix='fa'),
            tooltip="Mi ubicación"
        ).add_to(m)

        # Analizar amenazas
        threat_analysis = self.analyze_all_threats(geo_data)
        threat_by_ip = {t['ip']: t for t in threat_analysis['threat_details']}

        # Agregar marcador para cada IP geolocalizada
        for data in geo_data:
            if data and data['lat'] and data['lon']:
                # Obtener info del servicio
                service = self._get_service_info(data['ip'])

                # Verificar amenazas
                threat_info = threat_by_ip.get(data['ip'])
                if threat_info:
                    risk_color = 'darkred' if threat_info['risk_level'] == 'HIGH' else 'orange'
                    risk_icon = 'exclamation-triangle' if threat_info['risk_level'] == 'HIGH' else 'exclamation-circle'

                    threats_html = "<hr><b style='color:red'>⚠️ AMENAZAS DETECTADAS</b><br>"
                    for threat in threat_info['threats']:
                        threats_html += f"<span style='color:red'>• {threat['description']}</span><br>"

                    popup_html = f"""
                    <b>IP:</b> {data['ip']}<br>
                    <b>País:</b> {data['country']}<br>
                    <b>Ciudad:</b> {data['city']}<br>
                    <b>Región:</b> {data['region']}<br>
                    <b>Propietario/Org:</b> {data.get('org', 'Unknown')}<br>
                    <b>ISP:</b> {data['isp']}<br>
                    <b>ASN:</b> {data['asn']}<br>
                    <b>Zona Horaria:</b> {data.get('timezone', 'Unknown')}<br>
                    <hr>
                    <b>Servicio:</b> {service['name']}<br>
                    <b>Puerto:</b> {service.get('port', 'N/A')}
                    {threats_html}
                    """

                    marker_color = risk_color
                    marker_icon = risk_icon
                else:
                    popup_html = f"""
                    <b>IP:</b> {data['ip']}<br>
                    <b>País:</b> {data['country']}<br>
                    <b>Ciudad:</b> {data['city']}<br>
                    <b>Región:</b> {data['region']}<br>
                    <b>Propietario/Org:</b> {data.get('org', 'Unknown')}<br>
                    <b>ISP:</b> {data['isp']}<br>
                    <b>ASN:</b> {data['asn']}<br>
                    <b>Zona Horaria:</b> {data.get('timezone', 'Unknown')}<br>
                    <hr>
                    <b>Servicio:</b> {service['name']}<br>
                    <b>Puerto:</b> {service.get('port', 'N/A')}
                    <br><b style='color:green'>✓ Sin amenazas detectadas</b>
                    """

                    marker_color = service['color']
                    marker_icon = service['icon']

                folium.Marker(
                    location=[data['lat'], data['lon']],
                    popup=popup_html,
                    icon=folium.Icon(color=marker_color, icon=marker_icon, prefix='fa'),
                    tooltip=f"{service['name']} - {data['ip']}"
                ).add_to(m)

                # Línea de conexión siempre visible
                line_color = service['color']
                if threat_info:
                    line_color = 'darkred' if threat_info['risk_level'] == 'HIGH' else 'orange'

                folium.PolyLine(
                    locations=[
                        [MY_LAT, MY_LON],
                        [data['lat'], data['lon']]
                    ],
                    color=line_color,
                    weight=3 if threat_info else 2,
                    opacity=0.8 if threat_info else 0.7,
                ).add_to(m)

        return m


# ============================================================
# FUNCIÓN PRINCIPAL
# ============================================================
def main():
    """Función principal del programa."""

    print("=" * 50)
    print("GeoNetTracker - Geolocalizador de Tráfico de Red")
    print("=" * 50)
    print(f"Tu ubicación: {MY_LAT}, {MY_LON}")
    print(f"Duración de captura: {CAPTURE_DURATION} segundos")
    print("Presiona Ctrl+C para detener manualmente")
    print("=" * 50)

    # Verificar permisos de root
    if os.geteuid() != 0:
        print("ERROR: Este script requiere permisos de root.")
        print("Ejecuta con: sudo python3 main.py")
        sys.exit(1)

    # Inicializar tracker
    tracker = NetworkTracker()

    # Iniciar captura de tráfico
    print("\n[*] Iniciando captura de tráfico...")
    print("[*] Presiona Ctrl+C para detener\n")

    try:
        # Capturar paquetes
        sniff(
            prn=tracker.process_packet,
            count=PACKET_COUNT,
            timeout=CAPTURE_DURATION,
            store=0
        )
    except KeyboardInterrupt:
        print("\n[!] Captura interrumpida por el usuario")

    # Mostrar resultados de captura
    print(f"\n[*] Captura completada")
    print(f"[*] Total de IPs únicas encontradas: {len(tracker.ips_found)}")

    if not tracker.ips_found:
        print("[!] No se encontraron IPs externas")
        sys.exit(0)

    # Geolocalizar cada IP
    print("\n[*] Obteniendo geolocalización de IPs...")
    geo_data = []

    for i, ip in enumerate(tracker.ips_found, 1):
        print(f"    [{i}/{len(tracker.ips_found)}] Consultando {ip}...", end='\r')

        geo = tracker.get_geolocation(ip)
        if geo:
            geo_data.append(geo)
            service = tracker._get_service_info(ip)
            print(f"    [{i}/{len(tracker.ips_found)}] {ip} -> {geo.get('country', 'Unknown')} ({service['name']})")

        # Respetar límite de la API (45 req/min)
        time.sleep(1.5)

    print(f"\n[*] IPs geolocalizadas: {len(geo_data)}/{len(tracker.ips_found)}")

    if not geo_data:
        print("[!] No se pudo geolocalizar ninguna IP")
        sys.exit(0)

    # Analizar amenazas
    print("\n[*] Analizando amenazas...")
    threat_summary = tracker.analyze_all_threats(geo_data)

    print("\n" + "=" * 50)
    print("       ANÁLISIS DE AMENAZAS")
    print("=" * 50)
    print(f"Total de IPs analizadas: {threat_summary['total_ips']}")
    print(f"IPs sospechosas: {threat_summary['suspicious_ips']}")
    print(f"  - Alto riesgo: {threat_summary['high_risk']}")
    print(f"  - Medio riesgo: {threat_summary['medium_risk']}")
    print(f"  - Bajo riesgo: {threat_summary['low_risk']}")

    if threat_summary['threat_details']:
        print("\n[!] DETALLES DE AMENAZAS:")
        for threat in threat_summary['threat_details']:
            print(f"\n  IP: {threat['ip']} [RIESGO: {threat['risk_level']}]")
            for t in threat['threats']:
                print(f"    - {t['description']}")
    else:
        print("\n[✓] No se detectaron amenazas conocidas")

    print("=" * 50)

    # Crear mapa
    print("\n[*] Generando mapa interactivo...")
    network_map = tracker.create_map(geo_data)

    # Guardar mapa
    output_file = "network_map.html"
    network_map.save(output_file)

    print(f"[+] Mapa guardado en: {output_file}")
    print("[*] Abriendo en navegador...")

    # Abrir automáticamente el mapa
    try:
        subprocess.run(["xdg-open", output_file], check=False)
    except Exception:
        try:
            subprocess.run(["firefox", output_file], check=False)
        except Exception:
            try:
                subprocess.run(["google-chrome", output_file], check=False)
            except Exception:
                print(f"    Abre manualmente: {output_file}")

    print("\n" + "=" * 50)
    print("GeoNetTracker completado exitosamente")
    print("=" * 50)


# Punto de entrada
if __name__ == "__main__":
    main()
