#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SCRIPT DE SPOOFING DE IP
===============================
SE puede crear paquetes IP falsificados
"""

## LIBRERIAS UTILIZADAS
import socket # Comunicación de red (enviar y recibir paquetes)
import struct # Formato de datos binarios (paquete IP) (empaquetar y desempaquetar datos)
import random # Generar valores aleatorios (IDs de paquetes e IPs falsas)
import sys # Información del sistema (plataforma, versión de Python)
import time # Tiempo (pausar el programa)
import subprocess # Ejecutar comandos del sistema

def mostrar_banner(): # Muestra el banner del programa
    """Muestra el banner del programa"""
    print("\n" + "="*60)
    print("    SCRIPT DE SPOOFING DE IP BY JOSÉ")
    print("="*60)

def mostrar_menu(): # Muestra el menú principal
    """Muestra el menú principal"""
    print("\n MENÚ PRINCIPAL:")
    print("1.  Crear y enviar paquete TCP falsificado")
    print("2.  Salir")
    print("-" * 40)

def obtener_ip_destino(): # Pide al usuario la IP de destino
    """Pide al usuario la IP de destino"""
    print("\n CONFIGURAR IP DE DESTINO")
    print("-" * 30)
    
    while True:
        ip = input("Ingresa la IP de destino (ej: 1.1.1.1): ").strip()
        if validar_ip(ip): # Valida si la IP tiene formato correcto
            print(f" IP válida: {ip}")
            return ip
        else:
            print(" IP inválida. Formato correcto: 192.168.1.1")

def obtener_puerto_destino(): # Pide al usuario el puerto de destino
    """Pide al usuario el puerto de destino"""
    print("\n CONFIGURAR PUERTO DE DESTINO")
    print("-" * 35)
    
    while True:
        try:
            puerto = input("Ingresa el puerto de destino (1-65535): ").strip()
            puerto_int = int(puerto)
            if 1 <= puerto_int <= 65535:
                print(f"Puerto válido: {puerto_int}")
                return puerto_int
            else:
                print("Puerto inválido. Debe estar entre 1 y 65535")
        except ValueError:
            print(" Puerto inválido. Ingresa un número válido")

def obtener_puerto_origen(): # Pide al usuario el puerto origen falso
    """Pide al usuario el puerto origen falso"""
    print("\n CONFIGURAR PUERTO ORIGEN FALSO")
    print("-" * 40)
    
    while True:
        try:
            puerto = input("Ingresa el puerto origen falso (1-65535): ").strip()
            puerto_int = int(puerto)
            if 1 <= puerto_int <= 65535:
                print(f" Puerto origen falso: {puerto_int}")
                return puerto_int
            else:
                print(" Puerto inválido. Debe estar entre 1 y 65535")
        except ValueError:
            print(" Puerto inválido. Ingresa un número válido")

def validar_ip(ip): # Valida si la IP tiene formato correcto
    """Valida si una IP tiene formato correcto"""
    try:
        partes = ip.split('.') # Divide la IP en partes
        if len(partes) != 4: # Si la IP no tiene 4 partes, es inválida
            return False
        for parte in partes: # Si alguna parte no está entre 0 y 255, es inválida
            if not 0 <= int(parte) <= 255:
                return False
        return True
    except: # Si hay un error, la IP es inválida
        return False



def crear_paquete_tcp_manual(ip_origen, ip_destino, puerto_origen, puerto_destino):
    """
    Crea un paquete IP + TCP COMPLETAMENTE MANUAL
    
    """
    
    # PASO 1: Configurar valores del header IP
    print("PASO 1: Configurando header IP")
    print("-" * 40)
    
    version_ihl = 0x45  # IPv4 (4) + Header de 20 bytes (5)
    tos = 0             # Type of Service (normal) o sea trafico normal, sin prioridad
    total_length = 40   # 20 bytes IP + 20 bytes TCP (CORRECTO)
    identification = random.randint(1, 65535)  # ID único
    flags_fragment = 0  # Sin fragmentación no este fragmentado por simplicidad del paquete
    ttl = 64           # Time to Live (saltos) 64 es un valor estandar que permite que el paquete viaje por 64 routes antes de ser descartado
    protocol = 6       # TCP  que es 6 en la tabla de protocolos de IP
    checksum = 0       # Checksum IP, se deja 0 porque ubutnu lo calcula uatomaticamente 
    
    print(f"   Versión IPv4 + IHL: 0x{version_ihl:02x} ({version_ihl})") # 0x es para que se muestre en hexadecimal y 02x es para que se muestre con 2 digitos
    print(f"   Longitud total: {total_length} bytes (IP + TCP)")
    print(f"   Protocolo: {protocol} (TCP)")
    
    # PASO 2: Configurar valores del header TCP
    print(f"\nPASO 2: Configurando header TCP")
    print("-" * 40)
    
    seq_num = random.randint(1000, 999999)  # Número de secuencia
    ack_num = 0                             # Número de ACK por defecto es  porque es el primer paquete que se envia y no hay respuesta
    data_offset = 5                         # Longitud TCP (5 palabras de 4 bytes = 20 bytes)
    reserved = 0                            # Reservado (3 bits) por defecto es 0 porque no se usa en este caso
    flags = 0x02                           # Flags TCP: SYN (bit 1) por defecto es 0x02 porque es el primer paquete que se envia y no hay respuesta
    data_offset_and_reserved = (data_offset << 4) | reserved  # 4 bits offset + 4 bits reserved
    window = 8192                          # Tamaño de ventana (2 bytes) por defecto es 8192 porque es un valor estandar
    tcp_checksum = 0                       # Checksum TCP por defecto es 0 porque ubutnu lo calcula uatomaticamente
    urgent_ptr = 0                         # Puntero de urgencia por defecto es 0 porque no se usa en este caso
    
    print(f"   Puerto origen: {puerto_origen}")
    print(f"   Puerto destino: {puerto_destino}")
    print(f"   Número de secuencia: {seq_num}")
    print(f"   Flags TCP: SYN")
    
    # PASO 3: Convertir IPs a formato binario
    print(f"\nPASO 3: Convirtiendo IPs a formato binario")
    print("-" * 45)
    
    ip_origen_bin = socket.inet_aton(ip_origen)
    ip_destino_bin = socket.inet_aton(ip_destino)
    
    print(f"   IP origen '{ip_origen}' → {ip_origen_bin.hex()}")
    print(f"   IP destino '{ip_destino}' → {ip_destino_bin.hex()}")
    
    # PASO 4: Crear header IP
    print(f"\nPASO 4: Creando header IP")
    print("-" * 30)
    
    header_ip = struct.pack('!BBHHHBBH4s4s',
        version_ihl,        # 1 byte que es B por ser 1 byte
        tos,                # 1 byte que es B por ser 1 byte
        total_length,       # 2 bytes que es H por ser 2 bytes
        identification,     # 2 bytes que es H por ser 2 bytes
        flags_fragment,     # 2 bytes que es H por ser 2 bytes
        ttl,                # 1 byte que es B por ser 1 byte
        protocol,           # 1 byte que es B por ser 1 byte
        checksum,           # 2 bytes que es H por ser 2 bytes
        ip_origen_bin,      # 4 bytes que es 4s por ser 4 bytes
        ip_destino_bin      # 4 bytes que es 4s por ser 4 bytes
    )
    
    print(f"   Header IP creado: {len(header_ip)} bytes")
    print(f"   Datos IP en hex: {header_ip.hex()}")
    
    # PASO 5: Crear header TCP
    print(f"\nPASO 5: Creando header TCP")
    print("-" * 30)
    
    header_tcp = struct.pack('!HHLLBBHHH',
        puerto_origen,              # H bytes - Puerto origen por ser 2 bytes
        puerto_destino,             # H bytes - Puerto destino por ser 2 bytes  
        seq_num,                    # 4 bytes - Número de secuencia
        ack_num,                    # L bytes - Número de ACK por ser 4 bytes
        data_offset_and_reserved,   # B bytes - Data offset + reserved por ser 1 byte
        flags,                      # B bytes - Flags TCP por ser 1 byte
        window,                     # H bytes - Ventana por ser 2 bytes
        tcp_checksum,               # H bytes - Checksum TCP por ser 2 bytes
        urgent_ptr                  # H bytes - Puntero de urgencia por ser 2 bytes
    )
    
    print(f"   Header TCP creado: {len(header_tcp)} bytes")
    print(f"   Datos TCP en hex: {header_tcp.hex()}")
    
    # PASO 6: Combinar IP + TCP
    print(f"\nPASO 6: Combinando IP + TCP")
    print("-" * 35)
    
    paquete_completo = header_ip + header_tcp
    
    print(f"   Header IP: {len(header_ip)} bytes") ## len es para obtener el tamaño del header IP en bytes
    print(f"   Header TCP: {len(header_tcp)} bytes") ## len es para obtener el tamaño del header TCP en bytes
    print(f"   Total: {len(paquete_completo)} bytes") ## len es para obtener el tamaño del paquete completo en bytes
    
    print(f"\n PAQUETE TCP CREADO EXITOSAMENTE")
    print(f"   Tamaño total: {len(paquete_completo)} bytes")
    print(f"   Datos en hex: {paquete_completo.hex()}") ## hex es para obtener el paquete completo en hexadecimal porque es mas facil de leer
    
    return paquete_completo

########################################################
########################################################
########################################################
#Funciones auxiliares
########################################################
########################################################
#explicar librerias
def explicar_librerias(): # Explica las librerías usadas
    """Explica las librerías usadas""" 
    print("\n LIBRERÍAS UTILIZADAS")
    print("=" * 30)
    print(" socket:") ## socket:
    print("   - Crear sockets de red")
    print("   - Enviar paquetes")
    print("   - Convertir IPs a binario")
    print()
    print("struct:")
    print("   - Empaquetar datos en formato binario")
    print("   - Crear headers de red")
    print("   - Controlar el formato de bytes")
    print()
    print("random:")
    print("   - Generar IDs únicos para paquetes")
    print("   - Crear IPs falsas aleatorias")
    print()
    print("sys:")
    print("   - Información del sistema")
    print("   - Detectar plataforma")
   
#enviar paquete
def enviar_paquete(paquete, ip_destino, puerto_destino, puerto_origen, ip_falsa):
    """Envía el paquete a la dirección especificada"""
    try:
        # Crear socket raw (requiere permisos de administrador)
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        ## AF_INET es para indicar que se va a usar IPv4 y SOCK_RAW es para indicar que se va a usar raw socket
        ## socket.socket es para crear un socket, socket es la libreria usada

        ## raw socket es un socket que no usa protocolos de red, es decir, no usa IP, TCP, UDP, etc. solo se usa para enviar y recibir paquetes sin procesarlos
    
        ## IPPROTO_RAW es para indicar que se va a usar raw protocol que es el portocolo de red mas basico 
        sock.sendto(paquete, (ip_destino, puerto_destino))
        ## sendto es para enviar el paquete a la dirección especificada
        sock.close()
        
        print("\n¡PAQUETE ENVIADO EXITOSAMENTE!")
        print(f"Origen: {ip_falsa}:{puerto_origen}")
        print(f"Destino: {ip_destino}:{puerto_destino}")
        print("Abre Wireshark para ver el tráfico")
        print(f"Filtro sugerido: ip.dst == {ip_destino}")
        
    except PermissionError:
        print("ERROR: Necesitas permisos de administrador")
        print("   Ejecuta: sudo python3 ip_spoofing.py")
    except Exception as e:
        print(f" Error al enviar: {e}")



def generar_ip_falsa():
    """Genera una IP falsa aleatoria"""
    return f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"

def main():
    """Función principal del programa"""
    mostrar_banner()
    
    while True: # Mientras el usuario no quiera salir
        mostrar_menu() # Mostrar el menú principal
        opcion = input("\nSelecciona una opción (1-2): ").strip() # Pedir al usuario una opción
        
        if opcion == "1":
            # Crear y enviar paquete TCP
            print("\n CREAR PAQUETE TCP FALSIFICADO")
            print("=" * 40)
            
            # Pedir IP de destino
            ip_destino = obtener_ip_destino()
            
            # Pedir puerto de destino
            puerto_destino = obtener_puerto_destino()
            
            # Pedir IP falsa
            print(f"\n CONFIGURAR IP FALSA")
            print("-" * 25)
            while True:
                ip_falsa = input("Ingresa la IP falsa (origen): ").strip()
                if validar_ip(ip_falsa):
                    print(f"IP falsa válida: {ip_falsa}")
                    break
                else:
                    print(" IP inválida. Formato correcto: 192.168.1.1")
            
            # Pedir puerto origen falso
            puerto_origen = obtener_puerto_origen()
            
            # Mostrar resumen de configuración
            print(f"\n RESUMEN DE CONFIGURACIÓN")
            print("=" * 35)
            print(f"IP destino: {ip_destino}")
            print(f"Puerto destino: {puerto_destino}")
            print(f"IP falsa (origen): {ip_falsa}")
            print(f"Puerto origen falso: {puerto_origen}")
            
            # Crear paquete TCP
            paquete = crear_paquete_tcp_manual(ip_falsa, ip_destino, puerto_origen, puerto_destino)
            
            # Enviar paquete
            enviar_paquete(paquete, ip_destino, puerto_destino, puerto_origen, ip_falsa)
            
        elif opcion == "2":
            print("\n¡Hasta luego!")
            break
            
        else:
            print("Opción inválida")
        
        input("\nPresiona Enter para continuar...")

if __name__ == "__main__":
    main()

    ## para ver info de la WIFI
    ## iwconfig - ip a ip -4 addr show wlo1 | awk '/inet /{print $2}' | cut -d/ -f1

