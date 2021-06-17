from trex_stl_lib.api import *
import yaml
import shutil
import os
import json

from utils import stats_sum_dict, create_Field_Engine

# Añadir la librería al path
# export PYTHONPATH=/opt/trex/v2.87/automation/trex_control_plane/interactive

#Leemos el fichero config.yaml y lo guardamos en configuration
with open("./config.yaml", 'r') as stream:
    try:
        configuration = yaml.safe_load(stream)
    except yaml.YAMLError as exc:
        print(exc)
   
#Borramos el directorio de las capturas de la anterior ejecución     
dir_path = './Traffic_capture'
try:
  shutil.rmtree(dir_path)
except OSError as e:
  pass

#Creamos el nuevo directorio para las capturas
os.mkdir('Traffic_capture')

# Creamos un cliente dirigido al servidor lanzado en localhost
c = STLClient(server = "127.0.0.1")

#Nos conectamos al cliente
c.connect()


#Variables para guardar las estadísticas globales a mostrar por terminal
total_stats_tx = 0
total_stats_rx = 0

# Comienza la generación del tráfico
print("######## STARTING TO GENERATE TRAFFIC... ########\n")

# Paramos el tráfico, reseteamos las estadísticas y adquirimos los puertos
c.reset(ports = [0,1])

# Inicializamos la variable donde guardaremos las estadísticas globales completas del tráfico
stats_sum = {}


# Recorremos todos los tipos de tráfico
for value in configuration['simulated']:

# Si existen clientes en el tipo de tráfico lo generamos
  if value['users'] > 0:
  
    #Creamos el Field Engine para el tipo de tráfico en concreto
    if "IP_src" in value and "IP_dst" in value:
      vm = create_Field_Engine(value['IP_src']['src1'], value['IP_src']['src2'], value['IP_src']['op'], value['IP_dst']['dst1'], value['IP_dst']['dst2'], value['IP_dst']['op']) 
    elif "IP_src" in value and "IP_dst" not in value:
      vm = create_Field_Engine(value['IP_src']['src1'], value['IP_src']['src2'], value['IP_src']['op'], configuration['IP_dst']['dst1'], configuration['IP_dst']['dst2'], configuration['IP_dst']['op'])  
    elif "IP_src" not in value and "IP_dst" in value:
      vm = create_Field_Engine(configuration['IP_src']['src1'], configuration['IP_src']['src2'], configuration['IP_src']['op'], value['IP_dst']['dst1'], value['IP_dst']['dst2'], value['IP_dst']['op'])
    else:
      vm = create_Field_Engine(configuration['IP_src']['src1'], configuration['IP_src']['src2'], configuration['IP_src']['op'], configuration['IP_dst']['dst1'], configuration['IP_dst']['dst2'], configuration['IP_dst']['op'])

    # Eliminamos los streams de los puertos
    c.remove_all_streams(ports = [0,1])
    
    # Limpiamos las estadísticas
    c.clear_stats() 
    
    # Comenzamos las captura del tráfico enviado por el puerto 0 y recibido por el 1 para generar los fichero pcap
    id = c.start_capture(tx_ports = [0], rx_ports = [1])
    
    # Reseteamos la variable
    stream = None

    # Convertimos el fichero pcap en una lista de streams conectados y personalizados con el número de clientes y el Field Engine definido
    stream = STLProfile.load_pcap(value['pcap_file'], ipg_usec = 1000, loop_count = value['users'], vm = vm).get_streams()

    # Añadimos el stream al puerto 0 para enviarlo
    c.add_streams(stream, ports = [0])

    # Comienza el tráfico en el puerto 0
    c.start(ports = [0])

    # Esperamos hasta que termine la transmisión de paquetes
    c.wait_on_traffic(ports = [0,1])

    # Obtenemos las estadísticas
    stats = c.get_stats()
    
    # Llamamos a la función stats_sum_dict() de utils.py para crear las estadísticas globales
    stats_sum = stats_sum_dict(stats, stats_sum)
         
    # Printeamos por terminal información del tipo de tráfico 
    print(value['text']+":\n")
    opackets = stats[0]['opackets']
    ipackets = stats[1]['ipackets']
    print("{0} packets were Tx on port {1}\n".format(opackets, 0))
    print("{0} packets were Rx on port {1}\n".format(ipackets, 1))
    
    print("--------------------------------------------------------------------------\n")
  
    # Sumamos el total de paquetes enviados y recibidos
    total_stats_tx += opackets
    total_stats_rx += ipackets
    
    # Paramos la captura del tráfico en el fichero pcap
    c.stop_capture(capture_id = id['id'], output = value['capture_file'])

# Printeamos por terminal información global sobre el tráfico generado
print("######## TRAFFIC GENERATION FINISHED ########\n")
print("TOTAL STATS:\n")
print("{0} packets were Tx on port {1}\n".format(total_stats_tx, 0))
print("{0} packets were Rx on port {1}\n".format(total_stats_rx, 1))

# Guardamos en un fichero json el resultado de completo de las estadísticas globales
with open('global_stats.json', 'w') as fp:
    json.dump(stats_sum, fp)





