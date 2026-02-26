# Geonettracker proyecto: Geolocalizar IPs, Folium mapa, README, main.py, commits

**Session ID:** ses_366d60341ffepM0brqvpBMhFf4
**Created:** 2/26/2026, 9:56:31 AM
**Updated:** 2/26/2026, 10:28:06 AM

---

## User

Actua como un ingeniero de Ciberseguridad y desarrollador de python. Necesito crear un proyecto en llamado GeoNetTracker siguiendo estas reglas estrictas: 1. No puedo escribir codigo todo debe ser generado por ti. 2. El objetivo es identificar IPs externas, geolocalizarlas mediante una API y generar un mapa interactivo HTML usuando folium que muestre lineas de ubicacion desde mi ubicacion 4. proporcioname : -El contenido de un README.md profesional con instrucciones de instalacion y uso si hay un README.md modificalo.  -Los comandos de terminal necesarios para instalr las dependencias(scapy, folium, requests) solucionando el error de externally-managed-environment. -El codigo del script main.py bien comentado. -Una lista de 5 mensajes de commit para mi historial de github que reflejen el progreso del proyecto. NO HAY QUE CREAR REPOSITORIO YA ESTA CREADO.

---

## Assistant

```
Tool: glob
```

---

## Assistant

```
Tool: read
```

---

## Assistant

Aquí tienes todo lo solicitado:

---

## 📄 README.md (Contenido profesional)

```markdown
# GeoNetTracker

Herramienta de ciberseguridad para identificar conexiones externas, geolocalizarlas y visualizarlas en un mapa interactivo.

## Descripción

GeoNetTracker es una herramienta que captura tráfico de red saliente, extrae direcciones IP externas, las geolocaliza utilizando la API de ip-api.com y genera un mapa interactivo HTML con Folium que muestra líneas de conexión desde tu ubicación hacia las IPs detectadas.

## Características

- Captura de tráfico de red saliente usando Scapy
- Geolocalización de IPs mediante API gratuita (ip-api.com)
- Mapa interactivo con Folium
- Visualización de conexiones en mapa mundial

## Requisitos

- Python 3.8+
- Sistema operativo: Linux/macOS (requiere permisos de root para Scapy)

## Instalación

### 1. Clonar el repositorio

```bash
git clone https://github.com/tu-usuario/GeoNetTracker.git
cd GeoNetTracker
```

### 2. Crear entorno virtual (recomendado)

```bash
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
```

### 3. Instalar dependencias

```bash
pip install --break-system-packages scapy folium requests
```

O si prefieres sin romper el entorno:

```bash
pip install --user scapy folium requests
```

## Configuración

Edita el archivo `main.py` y ajusta las siguientes variables según tu ubicación:

```python
# Tus coordenadas de ubicación
MY_LAT = 40.416775  # Latitud de tu ubicación
MY_LON = -3.703790  # Longitud de tu ubicación
```

## Uso

### Ejecución básica (requiere permisos de root)

```bash
sudo python3 main.py
```

El script:
1. Capturará tráfico de red saliente durante ~60 segundos
2. Extraerá IPs únicas del tráfico
3. Consultará la geolocalización de cada IP
4. Generará un archivo `network_map.html`
5. Abrirá automáticamente el mapa en tu navegador

### Ver el mapa

Abre el archivo generado en tu navegador:

```bash
firefox network_map.html
# o
google-chrome network_map.html
```

## Estructura del proyecto

```
GeoNetTracker/
├── README.md
└── main.py
```

## Notas de seguridad

- Scapy requiere permisos de root para capturar paquetes
- La API de geolocalización tiene límite de 45 peticiones/minuto (versión gratuita)
- Esta herramienta es para propósitos educativos y de auditoría de red autorizados

## Licencia

MIT License
```

---

## 📦 Comandos para instalar dependencias

```bash
# Opción 1: Con --break-system-packages (recomendado para sistemas Debian/Ubuntu)
sudo pip install --break-system-packages scapy folium requests

# Opción 2: Entorno virtual (más seguro)
python3 -m venv venv
source venv/bin/activate
pip install scapy folium requests

# Opción 3: Con --user (sin sudo)
pip install --user scapy folium requests
```

---

## 🐍 main.py (Código bien comentado)

```python
#!/usr/bin/env python3
"""
GeoNetTracker - Herramienta de geolocalización de tráfico de red

Este script captura tráfico de red saliente, extrae IPs únicas,
las geolocaliza y genera un mapa interactivo con Folium.
"""

import sys
import subprocess
import time
from collections import defaultdict

from scapy.all import sniff, IP, TCP, UDP
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
                        'asn': data.get('as', 'Unknown')
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
                <b>ISP:</b> {data['isp']}<br>
                <b>ASN:</b> {data['asn']}
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
            print(f"    Abre manualmente: {output_file}")
    
    print("\n" + "=" * 50)
    print("GeoNetTracker completado exitosamente")
    print("=" * 50)


# Importar módulo os al final para verificar permisos
import os

# Punto de entrada
if __name__ == "__main__":
    main()
```

---

## 📝 Lista de 5 mensajes de commit

1. **feat: add project structure and initial setup** - Creación del proyecto GeoNetTracker con README.md básico documentando el propósito de geolocalización de conexiones de red

2. **feat: implement network packet capture with scapy** - Añadir script principal para capturar tráfico saliente usando Scapy, filtrar IPs privadas y extraer direcciones únicas

3. **feat: integrate ip-api geolocation service** - Implementar geolocalización de IPs mediante API gratuita, manejar errores y respetar límites de peticiones

4. **feat: generate interactive map with folium** - Crear mapa HTML interactivo con marcadores de ubicación, líneas de conexión desde la ubicación del usuario y información detallada por IP

5. **fix: add root permission check and improve output** - Añadir verificación de permisos de root para Scapy, mejorar mensajes de progreso y estructurar código en clases reutilizables

---

## User

creamelo en esta carpeta

---

## Assistant

```
Tool: write
```

---

## Assistant

```
Tool: write
```

---

## Assistant

Archivos creados en `/home/galacardenas/GeoNetTracker/`:

| Archivo | Descripción |
|---------|-------------|
| `README.md` | Documentación profesional del proyecto |
| `main.py` | Script principal con todas las funcionalidades |

---

**Para instalar dependencias:**

```bash
sudo pip install --break-system-packages scapy folium requests
```

**Para ejecutar:**

```bash
sudo python3 main.py
```

---

**5 mensajes de commit:**

1. `feat: add project structure and initial setup`
2. `feat: implement network packet capture with scapy`
3. `feat: integrate ip-api geolocation service`
4. `feat: generate interactive map with folium`
5. `fix: add root permission check and improve output`

---

## User

en el README.md tambien colocale el modo de ejecucion y tambien colocale el comando si pide permisos de root si no modificale el permiso de root

---

## Assistant

```
Tool: read
```

---

## Assistant

```
Tool: edit
```

---

## Assistant

```
Tool: edit
```

---

## Assistant

Listo. README.md actualizado con:

- **Método 1:** `sudo python3 main.py`
- **Método 2:** `sudo chown root:root main.py` + `sudo chmod +s main.py` + `./main.py`

También agregué una nota adicional de seguridad.

---

## User

sudo chown root:root main.py
sudo chmod +s main.py
./main.py cuando ejecuto el main.py me dice permiso denegado

---

## Assistant

```
Tool: bash
```

---

## Assistant

```
Tool: bash
```

---

## Assistant

El problema es que faltan permisos de ejecución. Ejecuta estos comandos:

```bash
sudo chmod u+s main.py   # setuid
sudo chmod +x main.py    # dar permiso de ejecución
./main.py
```

---

## User

ya verifique el mapa y el main funcionan perfectamente pero quisiera saber si esto me da la ubicacion aproximada o la ubicacion en tiempo real y y tambien esto solo funciona con la ip del dispositvo y muestra en que paises se esta conectando o compartiendo?

---

## Assistant

respondiendo a tus preguntas:

**1. ¿Ubicación aproximada o en tiempo real?**
> **Aproximada**. La geolocalización se basa en la IP pública, no usa GPS. Muestra la ubicación del servidor/ISP asociado a esa IP (ciudad, país). No es en tiempo real ni precisa a nivel de calle.

**2. ¿Solo funciona con la IP del dispositivo?**
> Exactamente. Captura el tráfico que **sale** de tu dispositivo, entonces muestra:
- IPs de sitios web que visitas
- Servidores de aplicaciones
- APIs a las que se conectan tus apps
- Servidores DNS
- Etc.

**3. ¿Muestra países donde se conecta/comparte?**
> Sí. El mapa muestra líneas desde tu ubicación hacia las IPs externas que tu dispositivo contacta, indicando el país/ciudad de cada conexión.

**En resumen:** Es una herramienta de **auditoría de red** que te permite visualizar geográficamente a qué partes del mundo tu dispositivo está enviando datos. Es útil para detectar conexiones inesperadas o conocer el flujo de tráfico de red.

---

## User

modifica el README.md y agrega el orden de la ejecucion y si tambien agrega las preguntas antes que me respondiste 

---

## Assistant

```
Tool: read
```

---

## Assistant

```
Tool: edit
```

---

## Assistant

Listo. README.md actualizado con:

- **Orden de ejecución completo** (pasos 1-4)
- **Método alternativo** con permisos persistentes
- **Sección de Preguntas Frecuentes** respondiendo:
  - ¿Ubicación en tiempo real o aproximada?
  - ¿Solo funciona con la IP del dispositivo?
  - ¿Muestra los países de conexión?

---

