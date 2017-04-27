"""
Autores: Melisa Garcia P. y Jose Luis Osorio Q.
Proyecto de grado: Sistema open source para la deteccion de ataques en paginas web maliciosas
Universidad Icesi, 2017
"""
from xml.dom.minidom import parse
from cachecontrol import CacheControl
import urllib2
import csv
import json
import requests
import whois
import csv

contadorRedirecciones = 0

#A1- Longitud
# Longitud de la url
def longitudURL(url):
    print "A1"
    #dataset=open("../recursos/dataset_1.txt", "r")
    #dataset = open(input_path)
        #for linea in input_path:
    print "Procesando la url: %s ..." %(url)
    longitud = len(url)       
    return longitud

#longitudURL("../recursos/convert_dataset0.txt")

"""
for index in range(0, 3):
    input_path = "../recursos/convert_dataset"+ `index`+".txt"
    longitudURL(input_path)

#longitudURL(input_path)
"""

#A2-Caracteres
# Total de caracteres extrannos de la URL
def caracteresExtranos(url):
    """Se encarga de contar la cantidad de caracteres extranos que hay 
    en una url
    url: la url que se va a analizar"""

    print "A2"
    #dataset=open("../recursos/dataset_1.txt", "r")
    #dataset = open(input_path)
    try:
        #for linea in input_path:
    
        contadorAlfabetico = sum(1 for c in url if c.isalpha()) #cuantas letras hay en la linea
        contadorNumero = sum(1 for c in url if c.isdigit()) #cuantos numero hay en la linea
        caracteresAlfabeticos = contadorNumero + contadorAlfabetico
        longitud = len(str(url)) #tamano de la linea
        canCaracteres = longitud - caracteresAlfabeticos
        print longitud - caracteresAlfabeticos
    except Exception:
        canCaracteres = "-1"
        print " A2 Error en la URL"+ input_path
            
    return canCaracteres

"""
for index in range(0, 3):
    input_path = "../recursos/convert_dataset"+ `index`+".txt"
#input_path = "../recursos/dataset_0.txt"
    caracteresExtranos(input_path)
"""

#A3- Nombre Dominio
# Nombre del dominio de la URL
def nombreDominio(input_path):
    print "A3"
    #dataset=open("../recursos/dataset_1.txt", "r")
    dataset = open(input_path)
    for linea in input_path:
        try:
            lineS = linea.split(';')
            lista = lineS[1].split("/")
            Li = lista[2]
            Li = Li.split(".")
       #Li= Li[0]
            if "www" in Li[0]:
                domainName = Li[1]
                print Li[1]
            else:
                domainName = Li[0]
                print Li[0]
        except Exception:
            domainName = "NA"
    return domainName

"""
for index in range(0, 3):
    input_path = "../recursos/convert_dataset"+ `index`+".txt"
    nombreDominio(input_path)
"""
#https://media.readthedocs.org/pdf/requests-docs-es/latest/requests-docs-es.pdf

#A4-Charset
def HTTPHeader_charset(input_path):
    print "A4"
    #dataset=open("../recursos/dataset_0.txt", "r")
    dataset = open(input_path)
    for linea in input_path:
        try:
            lineS=linea.split(';')
            r = requests.get(lineS)
            charset = r.encoding
            print r.encoding
        except Exception:
            charset = "NA"
            print "A4 Error en la URL"+ linea
            
    return charset



#input_path = "../recursos/dataset_0.txt"
#HTTPHeader_charset()

#A5-Servidor web
def HTTPHeader_server(input_path):
    print "A5"
    #dataset=open("../recursos/dataset_1.txt", "r")
    dataset = open(input_path)
    for linea in input_path:
        try:
            lineS=linea.split(';')
            r = requests.get(lineS)
            rh = r.headers
            server = rh.get("server")
            print rh.get("server")
        except Exception:
            server = "NA"
            print "A5 Error en la URL "+ linea
            
    return server



"""
input_path = "../recursos/dataset_0.txt"
#HTTPHeader_server(input_path)
"""

#A6-Cache Control
def HTTPHeader_cacheControl(input_path):
    print "A6"
    #dataset=open("../recursos/dataset_1.txt", "r")
    dataset= open(input_path)
    for linea in input_path:
        try:
            lineS=linea.split(';')
            r = requests.get(lineS)
            rh = r.headers
            cacheC = rh.get("cache-control")
            print rh.get("cache-control")
        except Exception:
            cacheC = "NA"
            print "A6 Error en la URL "+linea
            
    return cacheC


"""
input_path = "../recursos/dataset_0.txt"
HTTPHeader_cacheControl(input_path)
"""

#A7-contentLength
def HTTPHeader_content_Length(input_path):
    print "A7"
    #dataset=open("../recursos/dataset_1.txt", "r")
    dataset = open(input_path)
    for linea in input_path:
        try:
            lineS=linea.split(';')
            r = requests.get(lineS)
            rh = r.headers
            contentL = rh.get("content-length")
            print rh.get("content-length")
        except Exception:
            contentL = "NA"
            print "A7 Error en la URL "+linea
            
    return contentL


"""
input_path = "../recursos/dataset_0.txt"
HTTPHeader_content_Length(input_path)
"""
#HOST INFORMATION

#A8- regDate 
def whois_regDate(input_path):
    print "A8" 
    #dataset=open("../recursos/dataset_1.txt", "r")
    dataset= open(input_path)
    for linea in input_path:
        try:
            lineS=linea.split(';')
            details = whois.whois(lineS)
            regD = details.creation_date
            print details.creation_date
        except Exception:
            regD = "NA"
            print "A8 Error en la URL "+ linea
            
    return regD

"""
input_path = "../recursos/dataset_0.txt"
whois_regDate(input_path)
"""

#A9-  Updated_date
def whois_Update_date(input_path):
    print "A9" 
    #dataset=open("../recursos/dataset_1.txt", "r")
    dataset = open(input_path)
    for linea in input_path:
        try:
            lineS=linea.split(';')
            details = whois.whois(lineS)
            update = details.updated_date
            print details.updated_date
        except Exception:
            update = "NA"
            print "A9 Error en URL "+ linea
            
    return update

"""
input_path = "../recursos/dataset_0.txt"
whois_Update_date(input_path)
"""

#A10 - Pais 
def whois_country(input_path):
    print "A10" 
    #dataset=open("../recursos/dataset_1.txt", "r")
    dataset = open(input_path)
    for linea in input_path:
        try:
            lineS=linea.split(';')
            details = whois.whois(lineS)
            count = details.country
            print details.country
        except Exception:
            count="NA"
            print "A10 Error al acceder a la URL "+ linea
            
    return count

"""
input_path = "../recursos/dataset_0.txt"
whois_country(input_path)
"""

#A11 - stateProv
def whois_StatePro(input_path):
    print "A11" 
    #dataset=open("../recursos/dataset_1.txt", "r")
    dataset = open(input_path)
    for linea in input_path:
        try:
            lineS=linea.split(';')
            details = whois.whois(lineS)
            stateP = details.state
            print details.state
        except Exception:
            stateP = "NA"
            print "Error A11 URL "+ linea
            
    return stateP

"""        
input_path = "../recursos/dataset_0.txt"
whois_StatePro(input_path)
"""

#A12 Within domain
def withinDomain(input_path):
    print "A12" 
    #dataset=open("../recursos/dataset_1.txt", "r")
    dataset = open(input_path)
    for linea in input_path:
        try:
            lineS=linea.split(';')
            details = whois.whois(lineS)
            domain = details.domain
            print details.domain
        except Exception:
            domain = "NA"
            print "A12 Error al acceder a la URL "+ linea
            
    return domain

"""
input_path = "../recursos/dataset_0.txt"
withinDomain(input_path)
"""
"""
#A13-Numero redirecciones
#Es un XML, lo que hace esto es leer el xml, identificar la etiqueta g y dentro de esta
#hay un atributo que es el id, este debe ser igual a node + un numero que es consecuente
def number_of_redirect(input_path_13,contadorRedirecciones):
    #documento=parse("D:/Desktop/MELISA/URL_1/analysis/graph.SVG")
    #documento=parse(input_path)
    for nodes in input_path_13.getElementsByTagName('g'):
        try:
            No=nodes.attributes['id'].value
            if "node" in No: 
                contadorRedirecciones=contadorRedirecciones+1
                redireccionesTotal=str(contadorRedirecciones)
                #print str(contadorRedirecciones)
        except Exception:
            redireccionesTotal= "-1"
            print "A13 Error en redirecciones "+ nodes
            pass
        
    return redireccionesTotal

"""
"""
for index in range(0, 3):
    input_path = "../script_python/thug/URL_D"+ `index`+"/analysis/graph.SVG"
    redirecciones(input_path, contadorRedirecciones)
"""    

def creacion_matriz_aplicacion(input_path, ruta_matriz_app):

    with open(name = input_path, mode='r', buffering = 1) as datasets:
         with open(name = ruta_matriz_app, mode ='a+') as matrizApp:
            for linea in datasets:
                try:
                    contenido = linea.split(';')
                    id_url = contenido[0]
                    url = contenido[1]
                    matrizApp.writelines(id_url + ';' 
                                        + str(longitudURL(url)) + ';' 
                                        + str(caracteresExtranos(url)) + '\n')
                                        #+ nombreDominio(linea) + ';' 
                                        #+ HTTPHeader_charset(linea) + ';' 
                                        #+ HTTPHeader_server(linea) + ';' 
                                        #+ HTTPHeader_content_Length(input_path) + ';' 
                                        #+ whois_regDate(input_path) + ';' 
                                        #+ whois_Update_date(input_path) + ';' 
                                        #+ whois_country(input_path) + ';' 
                                        #+ whois_StatePro(input_path) + ';' 
                                        #+ withinDomain(input_path) + '\n')
                                        #+ number_of_redirect(input_path_13, contadorRedirecciones)+ '\n')
                except Exception, e:
                    print e
                
        

for index in range(0,3):
    #input_path_13="../script_python/thug/URL_D"+ `index`+"/analysis/graph.SVG"
    input_path ="../recursos/convert_dataset"+ `index`+".txt"
    ruta_matriz_app = "../recursos/matrizAplicacion.csv"
    creacion_matriz_aplicacion(input_path,ruta_matriz_app)

"""
#A14- Number of embedded externar URLs
def numberEmbeddedExternal():


numberEmbeddedExternal()

#A15- Content length valid
def contentLengthValid():


contentLengthValid()    

#A16-Number of long strings
def numberLongString():

numberLongString()

#A17 A18- Number of iframe and number of small
def numberIframesSmall():


numberIframesSmall()

#A19- number of suspicious JS functions
def numberSuspiciousJS_functions():


numberSuspiciousJS_functions()
"""






