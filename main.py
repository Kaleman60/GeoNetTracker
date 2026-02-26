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

from scapy.all import sniff, IP
import folium
import requests


# ============================================================
# CONFIGURACIÓN - Ajusta estas coordenadas a tu ubicación
# ============================================================
MY_LAT = 40.416775   # Latitud de tu ubicación (ej: Madrid)
MY_LON = -3.703790   # Longitud de tu ubicación (ej: Madrid)

# Configuración de captura
CAPTURE_DURATION = 60  # Duración de captura en segundos
PACKET_COUNT = 1000    # Número máximo de paquetes a capturar

# URL de la API de geolocalización (gratuita)
GEO_API_URL = "http://ip-api.com/json/"


# ============================================================
# CLASE PARA GESTIONAR CONEXIONES
# ============================================================
class NetworkTracker:
    """Clase principal para rastrear conexiones de red."""

    def __init__(self):
        # Almacena IPs únicas encontradas
        self.ips_found = set()
        # Almacena conexiones por IP (origen -> destino)
        self.connections = defaultdict(int)

    def process_packet(self, packet):
        """
        Procesa cada paquete capturado.

        Args:
            packet: Paquete Scapy capturado
        """
        # Verificar que el paquete tiene capa IP
        if IP in packet:
            # Obtener IP de origen y destino
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Ignorar IPs privadas/reservadas
            if not self._is_private_ip(src_ip):
                self.ips_found.add(src_ip)
                self.connections[src_ip] += 1

            if not self._is_private_ip(dst_ip):
                self.ips_found.add(dst_ip)
                self.connections[dst_ip] += 1

    def _is_private_ip(self, ip):
        """
        Verifica si una IP es privada o reservada.

        Args:
            ip: Dirección IP a verificar

        Returns:
            bool: True si es IP privada/reservada
        """
        # Convertir IP a entero para comparación
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

        # Agregar marcador para tu ubicación
        folium.Marker(
            location=[MY_LAT, MY_LON],
            popup=f"<b>Tu Ubicación</b><br>Lat: {MY_LAT}<br>Lon: {MY_LON}",
            icon=folium.Icon(color='red', icon='home', prefix='fa'),
            tooltip="Mi ubicación"
        ).add_to(m)

        # Agregar marcador para cada IP geolocalizada
        for data in geo_data:
            if data and data['lat'] and data['lon']:
        # Marcador para la IP
        popup_html = f"""
        <b>IP:</b> {data['ip']}<br>
        <b>País:</b> {data['country']}<br>
        <b>Ciudad:</b> {data['city']}<br>
        <b>Región:</b> {data['region']}<br>
        <b>Propietario/Org:</b> {data.get('org', 'Unknown')}<br>
        <b>ISP:</b> {data['isp']}<br>
        <b>ASN:</b> {data['asn']}<br>
        <b>Zona Horaria:</b> {data.get('timezone', 'Unknown')}
        """

                folium.Marker(
                    location=[data['lat'], data['lon']],
                    popup=popup_html,
                    icon=folium.Icon(color='blue', icon='globe', prefix='fa'),
                    tooltip=f"{data['country']} - {data['ip']}"
                ).add_to(m)

                # Línea de conexión desde tu ubicación
                folium.PolyLine(
                    locations=[
                        [MY_LAT, MY_LON],
                        [data['lat'], data['lon']]
                    ],
                    color='blue',
                    weight=2,
                    opacity=0.6,
                    dash_array='5, 10'
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
            print(f"    [{i}/{len(tracker.ips_found)}] {ip} -> {geo.get('country', 'Unknown')}")

        # Respetar límite de la API (45 req/min)
        time.sleep(1.5)

    print(f"\n[*] IPs geolocalizadas: {len(geo_data)}/{len(tracker.ips_found)}")

    if not geo_data:
        print("[!] No se pudo geolocalizar ninguna IP")
        sys.exit(0)

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
