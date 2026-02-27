# GeoNetTracker

Herramienta de ciberseguridad para identificar conexiones externas, geolocalizarlas y visualizarlas en un mapa interactivo.

## Descripción

GeoNetTracker es una herramienta que captura tráfico de red saliente, extrae direcciones IP externas, las geolocaliza utilizando la API de ip-api.com y genera un mapa interactivo HTML con Folium que muestra líneas de conexión desde tu ubicación hacia las IPs detectadas.

## Características

- Captura de tráfico de red saliente usando Scapy
- Geolocalización de IPs mediante API gratuita (ip-api.com)
- **Detección de protocolos y puertos** (HTTPS, SSH, FTP, DNS, MySQL, etc.)
- **Líneas de conexión coloreadas** según el servicio
- **Mapa de calor de intensidad** para visualizar volumen de tráfico por región
- Visualización de conexiones en mapa mundial
- Información del propietario/ISP de cada IP
- Popup interactivo con detalles de cada conexión

## Requisitos

- Python 3.8+
- Sistema operativo: Linux/macOS (requiere permisos de root para Scapy)

## Instalación

### 1. Clonar el repositorio

```bash
git clone https://github.com/Kaleman60/GeoNetTracker.git
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

### Orden de ejecución completo

```bash
# 1. Instalar dependencias (solo una vez)
pip install --break-system-packages scapy folium requests

# 2. Configurar tu ubicación (editar main.py)
MY_LAT = 40.416775   # Tu latitud
MY_LON = -3.703790   # Tu longitud

# 3. Ejecutar el script
sudo python3 main.py

# 4. Ver el mapa generado
firefox network_map.html
```

### Método alternativo (con permisos persistentes)

```bash
sudo chown root:root main.py
sudo chmod u+s main.py
sudo chmod +x main.py
./main.py
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

## Preguntas Frecuentes

### ¿La ubicación es en tiempo real o aproximada?

La **aproximada geolocalización es**. Se basa en la IP pública del dispositivo, no usa GPS. Muestra la ubicación del servidor/ISP asociado a esa IP (ciudad, país). No es en tiempo real ni precisa a nivel de calle.

### ¿Solo funciona con la IP de mi dispositivo?

Sí. La herramienta captura el tráfico que **sale** de tu dispositivo, mostrando:
- IPs de sitios web que visitas
- Servidores de aplicaciones
- APIs a las que se conectan tus apps
- Servidores DNS
- Otros dispositivos de red

### ¿Muestra los países donde se conecta mi dispositivo?

Sí. El mapa genera líneas desde tu ubicación hacia las IPs externas que tu dispositivo contacta, indicando el país y ciudad de cada conexión.

## Nuevas Mejoras

### v2.0 - Detección de Protocolos y Puertos

- Identificación de servicios por puerto: HTTPS (443), HTTP (80), SSH (22), FTP (21), SMTP (25), DNS (53), MySQL (3306), PostgreSQL (5432), MongoDB (27017), RDP (3389)
- Líneas de conexión coloreadas según el tipo de servicio
- Marcadores con iconos diferenciados por protocolo
- Popup con información detallada del servicio

### v2.1 - Mapa de Calor de Intensidad

- Capa de calor superpuesta al mapa
- Visualización del volumen de tráfico por región
- Gradiente de colores: azul (bajo) → rojo (alto)
- Identificación rápida de zonas con mayor actividad de red
- Leyenda actualizada con interpretación del heatmap

### v2.2 - Información de Propietario

- Consultas WHOIS automáticas via API
- Muestra el propietario/organización del servidor
- Información del ISP (Internet Service Provider)
- Número de sistema autónomo (ASN)
- Zona horaria del servidor

### v2.3 - Detección de Tráfico Malicioso

- **Detección de puertos maliciosos**: Identifica conexiones a puertos conocidos por malware (Metasploit, NetBus, SubSeven, Back Orifice, etc.)
- **Alertas de puertos sensibles**: Detecta conexiones a servicios sensibles (SSH, RDP, SMB, Telnet, bases de datos)
- **Análisis de países de alto riesgo**: Identifica conexiones a países con alta actividad de amenazas (China, Rusia, Corea del Norte, Iran, etc.)
- **Niveles de riesgo**: Clasifica conexiones en ALTO, MEDIO y BAJO riesgo
- **Visualización en mapa**: Marcadores rojos para amenazas de alto riesgo, naranjas para medio riesgo
- **Resumen en consola**: Muestra estadísticas de amenazas detectadas al finalizar el escaneo

## Estructura del proyecto

```
GeoNetTracker/
├── README.md
└── main.py
```

## Notas de seguridad

- **Scapy requiere permisos de root** para capturar paquetes (usar `sudo` o `chown root:root` + `chmod +s`)
- La API de geolocalización tiene límite de 45 peticiones/minuto (versión gratuita)
- Esta herramienta es para propósitos educativos y de auditoría de red autorizados
- **No ejecutar en redes ajenas sin autorización**

## Licencia

MIT License
