from utils import db_handler
import hashlib
import os
from os import system, name
from pickle import FALSE
import re
import shutil
import stat
import geoip2.database
from models.Loginfalhados import Loginfalhados
from models.servicos import Servicos
from models.PortScanner import PortScanner
from models.user import User
from models.mensagem import Mensagem
from time import sleep
import stdiomask
from utils.colors import bcolors
from utils.rsa import RSACrifra
import pyfiglet
import sys
import socket
from datetime import datetime
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter, landscape
import csv
import matplotlib.pyplot as plt
import chat.servidor as servidor
import chat.cliente as cliente
import base64
import stdiomask
from port_knocking.knock import PortKnocker
RESULTADOS_DIR = os.path.join(
    os.path.expanduser("~"),
    "mesi_lpd_securityapp",
    "resultados"
)

os.makedirs(RESULTADOS_DIR, exist_ok=True)

# ========== FUNÇÃO clearScreen() ADICIONADA AQUI ==========
def clearScreen():
    """Limpa a tela do terminal."""
    os.system('cls' if os.name == 'nt' else 'clear')
# ==========================================================


sys.path.append(os.path.abspath(os.path.dirname(__file__)))

def autenticacao(username, password):
    db = db_handler.DB()
    query = "select * from utilizador where username = ?"
    user = db.select(query, (username,))
    
    if user:
        # Comparar a senha hasheada
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        if hashed_password == user[0][2]:  # user[0][2] é a senha hasheada no banco
            return user[0]  # Retorna os dados do usuário
        else:
            return 0  # Senha incorreta
    else:
        return 0  # Usuário não encontrado

def main():
    msg = pyfiglet.figlet_format("LPD - PYTHON")
    print(msg)
    print("**-**-**-**-**-**-**-**-**-**-**-**-**-**-**-**-**-****-****-****-****-****-****-**") 
    print(f"|{bcolors.OKBLUE}         INSTITUTO POLITÉCNICO DE BEJA{bcolors.ENDC}            |")
    print(f"|{bcolors.OKBLUE}          M E S I  2 0 2 5 - 2 0 2 6  {bcolors.ENDC}            |")
    print(f"|{bcolors.OKBLUE}   Projeto de Linguagem de Programação Dinâmica{bcolors.ENDC}   |")
    print("|---------------------------------------------------------------------------------|")
    print(f"|{bcolors.BOLD}     A P L I C A Ç Ã O   D E   S E G U R A N Ç A {bcolors.ENDC}   |")     
    print("|-------------------------------------------------------------------------------  |")
    print("|                            Aluno: Ze Manuel Gomes n 22276                       |")
    print("**-**-**-**-**-**-**-**-**-**-**-**-**-**-**-**-**-****-**-**-**-**-**-**-**-**-**-") 

    try:
       
        loginOuRegistar()
    except KeyboardInterrupt:
        print("\nPrograma interrompido abrupta !!!!")
        sys.exit()

def loginOuRegistar():
    print('\n-----------------------------------------------------')
    print("[1] LOGIN")
    print("[2] REGISTAR")
    
    op = input(f"\n{bcolors.BOLD}>>> {bcolors.ENDC}")    
    if op == '1':
        login()
    elif op == '2' : 
        registar()
    else:
        print("\nOpção Invalida\n")
        loginOuRegistar()

def login(): 
    print("\n-------------------- << LOGIN >> --------------------")
    username = input("Nome utilizador: ")
    password = stdiomask.getpass()  
    
    # Chamando a função de autenticação
    user = autenticacao(username, password)
    
    # Imprimir os dados retornados pela autenticação
    print(f"Dados do usuário retornados: {user}")
    
    if user != 0:
        print(f"Registar Log: sucesso - {user[1]}")
        registarLogs("sucesso", user[1], "login", "autenticação feita")
        menuPrincipal(user)
    else:
        print(f"{bcolors.FAIL}Autenticação inválida! \nUtilizador não encontrado{bcolors.ENDC}")
        registarLogs("erro", username, "login", "autenticação falhada")
        login()

# Caminho base para as chaves dentro do diretório correto
BASE_DIR = os.path.expanduser("~/mesi_lpd_securityapp") 

# Diretórios específicos para armazenar as chaves
CHAVES_PRIVADAS_DIR = os.path.join(BASE_DIR, "chavesprivadas")
CHAVES_PUBLICAS_DIR = os.path.join(BASE_DIR, "chavespublicas")

# Criar os diretórios caso não existam
os.makedirs(CHAVES_PRIVADAS_DIR, exist_ok=True)
os.makedirs(CHAVES_PUBLICAS_DIR, exist_ok=True)

def registar():
    print("\n------------------- << REGISTAR >> -------------------")

    username_raw = input("Nome utilizador: ")
    username = username_raw.strip().replace(" ", "").lower()

    password = stdiomask.getpass()
    passwordConfirmar = stdiomask.getpass(prompt='Confirmar Password: ')

    if password != passwordConfirmar:
        print("\nPassword não é igual ao confirmado\n")
        return registar()

    print("\nProcessando, por favor aguarde...")

    # Gerar par de chaves RSA
    rsa = RSACrifra()
    keypair = rsa.gerarParChaves()

    pubKey = rsa.chavePublica(keypair)
    pubKeyPEM = pubKey.export_key()

    privKeyPEM = rsa.chavePrivada(keypair)

    passwordHash = hashlib.sha256(password.encode('utf-8')).hexdigest()

    # Inserir utilizador
    user = User(username, passwordHash, '', 'normal')
    insert = user.insert()

    if insert != 0:
        caminhoPrivKey = os.path.join(CHAVES_PRIVADAS_DIR, f"{username}_privKey.pem")
        caminhoPubKey = os.path.join(CHAVES_PUBLICAS_DIR, f"{username}_pUK.pem")

        rsa.salvarChavePEM(pubKeyPEM, caminhoPubKey)
        rsa.salvarChavePEM(privKeyPEM, caminhoPrivKey)

        print(f"\n\033[92mUtilizador registado com sucesso\033[0m\n")
        print("Par de chaves gerado\n")
        print(f"\033[1mChave Privada: {caminhoPrivKey}\033[0m\n")

        registarLogs("sucesso", username, "registo_user", "Registo de novo utilizador")
        login()


def registarUserAdmin():
    totalUsers = User().contarUsers()
    if totalUsers == 0:
        passwordHash = hashlib.sha256('1234'.encode('utf-8')).hexdigest()
        user = User('007',passwordHash,'','admin')
        user.insert() 

def portScanner(user):
    print("\n--------------- << PORT SCANNER >> ---------------")
    ip_alvo = input("Introduza o IP do alvo [ex: 127.0.0.1]: ")
    
    # Reduzir o intervalo de portas para um valor padrão de 1 até 1024
    porto_inicial = 1
    porto_final = 1024

    try:
        # Confirmação do intervalo de portas
        porto_inicial = int(input("Porto inicial (default 1): ") or 1)
        porto_final = int(input("Porto final (default 1024): ") or 1024)
    except ValueError:
        print("Por favor insira números válidos para os intervalos de portas.")
        return

    print(f"\nInicio do Scanner: {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}")
    print(f"IP alvo: {ip_alvo}")
    print("Processando, Por favor aguarde...")

    # Scanner das portas (de 1 até 1024 ou até o valor inserido pelo usuário)
    open_ports = []
    for port in range(porto_inicial, porto_final + 1):
        result = os.popen(f"nc -zv -w1 {ip_alvo} {port} 2>&1").read()
        if "succeeded" in result:
            open_ports.append(port)
    
    if open_ports:
        print(f"\nPortas abertas no IP {ip_alvo}:")
        for port in open_ports:
            print(f"Porta {port} está aberta.")
    else:
        print(f"\nNenhuma porta aberta encontrada no IP {ip_alvo}.")
    
    registarLogs("sucesso", user[1], "port_scan", f"Portas abertas no IP {ip_alvo}")
    voltarMenuOuLogout(user)

def gerarRelatorioPortScannerPDF(nomeFicheiro,titulo,data, conteudo, portos):
     dataPadding = "_"+data.strftime("%Y%m%d%H%M")
     pdf = canvas.Canvas(pathApp("relatorios/"+nomeFicheiro+dataPadding+".pdf"))
     pdf.setLineWidth(.3)
     pdf.setFont('Helvetica', 12)
     pdf.drawString(500,750,data.strftime("%d/%m/%Y"))
     pdf.setFont('Helvetica-Bold', 18)
     pdf.drawString(200,735,'Relatorio '+titulo)
     pdf.line(20,700,580,700)
     pdf.setFont('Helvetica', 12)
     pdf.drawString(20,650,"IP Alvo: "+str(conteudo['ip']))
     pdf.drawString(300,650,"Portos ["+str(conteudo['pi'])+", "+str(conteudo['pf'])+"]")
     pdf.drawString(20,630,"Inicio: "+str(conteudo['di']))
     pdf.drawString(300,630,"Fim: "+str(conteudo['df']))
     pdf.line(20,615,580,615)
     pdf.setFont('Helvetica', 12)
    
     y = 600
     i = 0
     for linha in portos:
        i = i +1
        pdf.drawString(20, y, str(i)+". Porto aberto: "+str(linha))
        y -= 25  
        
     pdf.setFont('Helvetica-Bold', 12)        
     pdf.line(20,(y-20),580,(y-20))
     if len(portos) == 1:
         msg = str(len(portos))+ " porto aberto"
     else:
         msg = str(len(portos))+ " portos abertos"
     pdf.drawString(20,(y-35),"Total: "+msg)
                
     pdf.save()

def logout(username):
    print("\nTerminando a sessão...")
    registarLogs("sucesso",username,"login","logout")
      
    sleep(1)
    print("\nAdeus e Obrigado!")
    sys.exit()

def analiseLogServicos(user):
    print("\n------- << ANALISE LOGS SERVIÇOS [HTTP/SSH] >> ---------\n")

    ficheiro = input("Indique o ficheiro [caminho/ficheiro]: ").strip()

    try:
        if os.path.isabs(ficheiro):
            f = open(ficheiro, "r")
        else:
            f = open(pathApp(ficheiro, 1), "r")
    except FileNotFoundError:
        print(f"{bcolors.FAIL} Ficheiro não encontrado{bcolors.ENDC}")
        return

    print("Ficheiro aberto com sucesso!")

    linhas = f.readlines()
    f.close()

    cabecalho = ['Dia','Mes','Hora','Ip SRC','Ip DST','Porto DST','Cidade','Pais']
    dados = []
    res = 0

    for linha in linhas:
        if 'DPT=443' in linha or 'DPT=80' in linha:
            col = linha.split(' ')

            mes = col[0]
            dia = col[1]
            hora = col[2]
            ipSRC = col[11].replace('SRC=', '')
            ipDST = col[12].replace('DST=', '')
            dPort = col[21].replace('DPT=','')

            geoIp = GeoIpInfo(ipSRC)
            cidade = f"{geoIp.subdivisions.most_specific.name} ({geoIp.country.iso_code})"
            pais = geoIp.country.name

            dados.append([dia, mes, hora, ipSRC, ipDST, dPort, cidade, pais])

            servicos = Servicos(dia, mes, hora, ipSRC, ipDST, dPort, cidade, pais)
            res = servicos.insert()

    if res != 0:
        print(f"{bcolors.OKGREEN}\nOs dados foram guardados na base de dados{bcolors.ENDC}")

    registarLogs("sucesso", user[1], "analise_servico", "Analise de logs HTTP/HTTPS")

    # ===== CSV =====
    gerarFicheiroCSV("servicos", cabecalho, dados)

    while True:
        print("\n--------------------------------------------------")
        print("[1] Gerar Relatorio PDF")
        print("[2] Gerar grafico de Paises do IP de Origem [GeoIP]")
        print("[3] Voltar para o Menu Principal")

        op = input(f"\n{bcolors.BOLD}>>> {bcolors.ENDC}")

        if op == '1':
            print("Processando, Por favor aguarde...")
            sleep(1)
            gerarRelatorioLogServicosPDF(cabecalho, dados)
            print(f"{bcolors.OKGREEN}Relatorio gerado com sucesso{bcolors.ENDC}")
            registarLogs("sucesso", user[1], "relatorio", "Relatorio servicos")

        elif op == '2':
            IPs = []
            paises = []

            servicos = Servicos().selectIpSRCPorPais()
            for s in servicos:
                IPs.append(s[0])
                paises.append(s[1])

            plt.figure(figsize=(10,5))
            plt.bar(paises, IPs)
            plt.title('Grafico de IP por Paises de Origem')
            plt.xlabel('Paises')
            plt.ylabel('IPs')
            plt.grid(True)

            caminho_img = os.path.join(RESULTADOS_DIR, "grafico_paises_origem.png")
            plt.savefig(caminho_img)
            print(f" Gráfico guardado em: {caminho_img}")

            plt.show()
            registarLogs("sucesso", user[1], "grafico", "Grafico IP por pais")

        elif op == '3':
            return


def gerarRelatorioLogServicosPDF(cabecalho, dados):
    data = datetime.now()

    caminho_pdf = os.path.join(RESULTADOS_DIR, "servicos.pdf")
    pdf = canvas.Canvas(caminho_pdf)
    pdf.setPageSize(landscape(letter))
    pdf.setLineWidth(.3)
    pdf.setFont('Helvetica', 12)
    pdf.drawString(700, 570, data.strftime("%d/%m/%Y"))

    pdf.setFont('Helvetica-Bold', 18)
    pdf.drawString(220, 550, 'Relatorio Serviços HTTP / HTTPS')
    pdf.line(20, 530, 770, 530)

    # Cabeçalho
    pdf.setFont('Helvetica-Bold', 12)
    xCab = 20
    for c in cabecalho:
        pdf.drawString(xCab, 500, c)
        xCab += 100

    # Dados
    y = 480
    pdf.setFont('Helvetica', 12)
    for linha in dados:
        x = 20
        for campo in linha:
            pdf.drawString(x, y, str(campo))
            x += 100
        y -= 25

    pdf.save()
    print(f" Relatório guardado em: {caminho_pdf}")


def analiseLogsAuth(user):
    print("\n-------- << ANALISE LOG AUTH.LOG >> -----------\n")
    f = open("/home/kali/MESI_LPD_SecurityApp/logs/auth.log", "r")
    linhas = f.readlines()
    i=0
    cabecalho = ['Dia','Mes','Hora','IP','Porto','Cidade','Pais']
    dados = []
    res = 0
    import re
    re_ip = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}") 
    print("Processando, Por favor aguarde...")  
  
    for linha in linhas:
        if 'Failed password' in linha:
            i = i + 1                
            col = linha.split(' ')
            mes = col[0]
            dia = col[1]
            hora = col[2]
            ip = "".join(re.findall(re_ip,linha))
            re_porto = re.search(r'port\s(\w+)', linha)

            porto = re_porto.group(1)
            
            #passar o ip de origem para obter as informações das cidades
            geoIp = GeoIpInfo(str(ip))
            cidade = str(geoIp.city.name)+" ("+str(geoIp.country.iso_code)+")"
            pais = geoIp.country.name
            dados.append([dia,mes,hora,ip,porto,cidade,pais])
            
            print(str(dia)+" "+mes+" "+hora+" "+ip+" "+porto+" "+cidade+" "+pais)
                        
            #inserindo os dados na Base de Dados
            loginfalhados = Loginfalhados(str(dia),mes,str(hora),ip,str(porto),cidade,pais)
            res = loginfalhados.insert()
            
    if res != 0:
       print(f"{bcolors.OKGREEN}\nOs dados foram guardados na base de dados{bcolors.ENDC}")            
    
    registarLogs("sucesso",user[1],"analise_log_auth","Analise dos logs, filtragem dos logins falhados")
       
    #gerar ficheiro CSV dos login falhados 
    gerarFicheiroCSV("loginfalhados",cabecalho,dados)
    op=""
    while op != 3:
        print("\n------------------------------------------------")
        print("[1] Gerar Relatorio PDF")
        print("[2] Grafico de IP dos Login Falhados por Paises de origem [GeoIP]")
        print("[3] Voltar para o Menu Principal")
        
        op = input(f"\n{bcolors.BOLD}>>> {bcolors.ENDC}")
        if op =='1':
            print("Processando, Por favor aguarde...")
            sleep(1) 
            #faz a criação do pdf            
            gerarRelatorioLoginFalhadoPDF(cabecalho,dados)
            print(f"\n{bcolors.OKGREEN}Relatorio gerado com sucesso{bcolors.ENDC} \n")
            registarLogs("sucesso",user[1],"relatorio","relatorios dos logins falhados")
  
        elif op == '2':
            IPs = []
            paises =[]
            loginfalhados = Loginfalhados().selectIpLoginFalhadoPorPaises()
            for s in loginfalhados:
                IPs.append(s[0])
                paises.append(s[1])
            
            plt.barh(paises,IPs)
            plt.title('Grafico de IP dos Login Falhados por Paises de origem')
            plt.xlabel('IPs',fontsize=14)
            plt.ylabel('Paises',fontsize=14)
            plt.grid(True)
            plt.show()
            registarLogs("sucesso",user[1],"grafico","Grafico de IP dos Login Falhados por Paises de origem")
        else:
            menuPrincipal(user)

def gerarRelatorioLoginFalhadoPDF(cabecalho, dados):
    data = datetime.now()
    caminho_relatorio = "/home/kali/MESI_LPD_SecurityApp/relatorios/loginfalhados.pdf"
    
    # Verifica se o diretório 'relatorios' existe, senão cria
    if not os.path.exists(os.path.dirname(caminho_relatorio)):
        os.makedirs(os.path.dirname(caminho_relatorio))

    # Criar o PDF
    pdf = canvas.Canvas(caminho_relatorio)
    pdf.setPageSize(landscape(letter))
    pdf.setLineWidth(.3)
    pdf.setFont('Helvetica', 12)
    pdf.drawString(700, 570, data.strftime("%d/%m/%Y"))
    pdf.setFont('Helvetica-Bold', 18)
    pdf.drawString(220, 550, 'Relatorio de Login Falhados')
    pdf.line(20, 530, 770, 530)
     
    pdf.setFont('Helvetica-Bold', 12)     
    xCab = 20
    for c in cabecalho:
        pdf.drawString(xCab, 500, c)
        xCab += 100  

    y = 480   
    pdf.setFont('Helvetica', 12)        
    for celulas in dados:
        x = 20
        for c in celulas:
            pdf.drawString(x, y, str(c))  # Garante que o valor é string
            x += 100 
        y -= 25
    
    # Salvar o PDF
    pdf.save()
    print(f" Relatório gerado com sucesso: {caminho_relatorio}")

def gerarFicheiroCSV(ficheiro, cabecalho, dados):
    caminho_arquivo = os.path.join(RESULTADOS_DIR, f"{ficheiro}.csv")

    with open(caminho_arquivo, 'w', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(cabecalho)
        for dado in dados:
            writer.writerow(dado)

    print(f" Ficheiro CSV guardado em: {caminho_arquivo}")


def GeoIpInfo(ip):
    db_path = os.path.join(os.path.expanduser("~"), "mesi_lpd_securityapp", "utils", "GeoLite2-City.mmdb")
    reader = geoip2.database.Reader(db_path)
    response = reader.city(ip)
    reader.close()
    return response

def backup(user):
    print("\n------------------ << BACKUP >> ------------------")

    projeto_dir = os.path.dirname(os.path.abspath(__file__))
    backup_dir = os.path.join(projeto_dir, "backup")
    os.makedirs(backup_dir, exist_ok=True)

    nomeFicheiro = "backup_" + datetime.now().strftime("%d%m%Y%H%M%S") + ".zip"
    caminho_backup = os.path.join(backup_dir, nomeFicheiro)

    print("Processando, Por favor aguarde...")

    try:
        import zipfile

        with zipfile.ZipFile(caminho_backup, "w", zipfile.ZIP_DEFLATED) as zipf:
            for pasta, subpastas, ficheiros in os.walk(projeto_dir):
                if os.path.abspath(backup_dir) in os.path.abspath(pasta):
                    continue

                for ficheiro in ficheiros:
                    caminho_completo = os.path.join(pasta, ficheiro)
                    caminho_zip = os.path.relpath(caminho_completo, projeto_dir)
                    zipf.write(caminho_completo, caminho_zip)

        print(f"\n{bcolors.OKGREEN}Backup efetuado com sucesso!{bcolors.ENDC}")
        print(f"Nome do ficheiro: {nomeFicheiro}")
        print(f"Localização: {backup_dir}\n")

        registarLogs("sucesso", user[1], "backup", "Backup do projeto")

    except Exception as e:
        print(f"\n{bcolors.FAIL} Erro ao criar backup: {e}{bcolors.ENDC}")
        registarLogs("erro", user[1], "backup", str(e))

    input("\nPressione ENTER para continuar...")



def listarMsgChat(user):
    print("\nProcessando, por favor aguarde...")
    rsa = RSACrifra()

    # carregar chave privada
    if user[3] == "":
        ficheiro = input("Introduza o ficheiro da chave privada: ").strip()
        privKey = rsa.lerChavePEM(ficheiro)
        if not privKey:
            print(" Chave privada inválida")
            input("ENTER para voltar...")
            return
    else:
        privKey = rsa.lerChavePEM(user[3])

    mensagens = Mensagem().selectAll("user", user[1], "1")

    if not mensagens:
        print("\nNenhuma mensagem encontrada.")
        input("ENTER para voltar...")
        return

    print("\n------ MENSAGENS RECEBIDAS ------")
    for i, m in enumerate(mensagens, 1):
        criptograma = base64.b64decode(m[2])
        texto = rsa.decifrar(privKey, criptograma)
        print(f"{i}. [{m[1]}] {texto}")

    input("\nENTER para voltar ao menu...")

def apagarMsgChat(user):
    op =input("\nEliminar todas as mensagens? [y/n]: ")
    if op == 'y':
      delMsg = Mensagem().delete(user[1])
      if delMsg != 0 :
          print(f'{bcolors.OKGREEN}Mensagens eliminadas com sucesso{bcolors.ENDC}\n')
          registarLogs("sucesso",user[1],"chat_msg_del","Eliminação das mensagens")
    else:
        print("Operação cancelada")
        registarLogs("sucesso",user[1],"chat_msg_del","Tentativa de eliminação das mensagens")
        
    op =input("\nDesejas efetuar mais operações? [y/n]: ")
    if op == 'y':
        submenuChat(user)
    else:
        logout(user[1])

def submenuChat(user):
    print("\n-------------------- << CHAT >> --------------------")    
    print("[1] LISTAR MINHAS MENSAGENS")
    print("[2] APAGAR MINHAS MENSAGENS")
    print("[3] INICIAR CONVERSA")
    print("[4] VOLTAR AO MENU PRINCIPAL")
    print("[S] SAIR")    
    
    op = input(f"\n{bcolors.BOLD}>>> {bcolors.ENDC}")
    if op == '1':
          listarMsgChat(user)
    elif op == '2':
          apagarMsgChat(user)
    elif op == '3':
          cliente.enviarMensagem(user[1])
          submenuChat(user)     
    elif op == '4':
        menuPrincipal(user)
    elif op.lower() == 's':
        logout(user[1])
    else:
        print("Opcção Invalida!")
        submenuChat(user)

def registarLogs(status, username, acao, descricao):
    import os

    log_dir = os.path.join(
        os.path.expanduser("~"),
        "mesi_lpd_securityapp",
        "logs"
    )

    # Criar diretório se não existir
    os.makedirs(log_dir, exist_ok=True)

    log_path = os.path.join(log_dir, "logApp.log")

    try:
        with open(log_path, "a") as f:
            f.write(f"{status} - {username} - {acao} - {descricao}\n")
    except Exception as e:
        print(f"Erro ao registrar log: {e}")


def pathApp(ficheiro, flag=0):
    pathParte = "Desktop/LPD/lpdpython/aplicacao/"+ficheiro;
    if flag == 0:
        path = os.path.join(os.path.join(os.path.expanduser('~')),pathParte)
    else:
        path = os.path.join(os.path.join(os.path.expanduser('~')),ficheiro)
    return path

def udp_flood_attack(user):
   
    print("\n" + "="*50)
    print(" UDP FLOOD ATTACK - FERRAMENTA DE SEGURANÇA")
    print("="*50)
    
    # Input do usuário
    target_ip = input(" IP do alvo: ").strip()
    
    try:
        target_port = int(input(" Porta do alvo (ex: 80, 443): ").strip())
        duration = int(input("  Duração (segundos): ").strip())
        packet_size = input(" Tamanho do pacote [1024]: ").strip()
        packet_size = int(packet_size) if packet_size else 1024
    except ValueError:
        print(" Erro: Valores inválidos!")
        return
    
    print("\n" + "="*50)
    print("  AVISO: Use apenas para testes em ambientes controlados!")
    print("="*50)
    
    confirm = input("\n Confirmar ataque? (s/N): ").strip().lower()
    if confirm != "s":
        print(" Ataque cancelado!")
        return
    
    # Importar e executar o ataque
    try:
        from attacks.udp_flood import udp_flood
        udp_flood(target_ip, target_port, duration, packet_size)
        registarLogs("sucesso", user[1], "udp_flood", f"Ataque UDP para {target_ip}:{target_port}")
    except ImportError as e:
        print(f" Erro: Não foi possível importar módulo UDP Flood: {e}")
    except Exception as e:
        print(f" Erro durante o ataque: {e}")
        registarLogs("erro", user[1], "udp_flood", str(e))

def syn_flood_attack(user):
    
    print("\n" + "="*50)
    print(" SYN FLOOD ATTACK - FERRAMENTA DE SEGURANÇA")
    print("="*50)
    print("  REQUER PRIVILÉGIOS DE ROOT/ADMINISTRADOR!")
    print("="*50)
    
    # Input do usuário
    target_ip = input(" IP do alvo: ").strip()
    
    try:
        target_port = int(input(" Porta do alvo (ex: 80, 443): ").strip())
        duration = int(input("  Duração (segundos): ").strip())
        threads = input(" Threads [5]: ").strip()
        threads = int(threads) if threads else 5
    except ValueError:
        print(" Erro: Valores inválidos!")
        return
    
    print("\n" + "="*50)
    print("  AVISO: Use apenas para testes em ambientes controlados!")
    print("  Este ataque requer privilégios de root!")
    print("="*50)
    
    confirm = input("\n Confirmar ataque? (s/N): ").strip().lower()
    if confirm != 's':
        print(" Ataque cancelado!")
        return
    
    # Importar e executar o ataque
    try:
        from attacks.syn_flood import syn_flood
        syn_flood(target_ip, target_port, duration, threads)
        registarLogs("sucesso", user[1], "syn_flood", f"Ataque SYN para {target_ip}:{target_port}")
    except ImportError as e:
        print(f" Erro: Não foi possível importar módulo SYN Flood: {e}")
    except Exception as e:
        print(f" Erro durante o ataque: {e}")
        registarLogs("erro", user[1], "syn_flood", str(e))

# ========== FUNÇÕES PORT KNOCKING ==========
def menu_port_knocking(user):
    knocker = PortKnocker(lambda msg: registarLogs("info", user[1], "port_knock", msg))
    
    while True:
        print("\n" + "="*60)
        print(" PORT KNOCKING CLIENT")
        print("="*60)
        print("[1] Executar Port Knocking")
        print("[2] Configurar Firewall (Requer Sudo)")
        print("[3] Testar Conexão SSH")
        print("[4] Definir Nova Sequência")
        print("[5] Ver Sequência Atual")
        print("[0] Voltar ao Menu Principal")
        print("="*60)
        
        opcao = input(f"\n{bcolors.BOLD}>>> {bcolors.ENDC}").strip()
        
        if opcao == "1":
            executar_knocking(user, knocker)
        elif opcao == "2":
            configurar_firewall_knocking(user, knocker)
        elif opcao == "3":
            testar_ssh(user, knocker)
        elif opcao == "4":
            definir_sequencia(knocker)
        elif opcao == "5":
            print(f"\n Sequência atual: {knocker.sequence}")
            print(f" Porta SSH: {knocker.ssh_port}")
            print(f"  Duração abertura: {knocker.open_duration} segundos")
        elif opcao == "0":
            break
        else:
            print(f"\n{bcolors.FAIL} Opção inválida!{bcolors.ENDC}")
        
        input(f"\n{bcolors.OKBLUE}Pressione Enter para continuar...{bcolors.ENDC}")

def executar_knocking(user, knocker):
    print("\n" + "="*50)
    print(" EXECUTAR PORT KNOCKING")
    print("="*50)
    
    target_ip = input("IP do servidor alvo: ").strip()
    
    if not target_ip:
        print(f"{bcolors.FAIL} IP é obrigatório!{bcolors.ENDC}")
        return
    
    usar_personalizada = input("Usar sequência personalizada? (s/N): ").lower().strip()
    
    sequence = None
    if usar_personalizada == "s":
        seq_input = input("Digite portas separadas por vírgula (ex: 1000,2000,3000): ").strip()
        if seq_input:
            try:
                sequence = [int(p.strip()) for p in seq_input.split(",")]
                if len(sequence) < 2:
                    print(f"{bcolors.FAIL} Precisa de pelo menos 2 portas!{bcolors.ENDC}")
                    return
            except ValueError:
                print(f"{bcolors.FAIL} Formato inválido! Use números.{bcolors.ENDC}")
                return
    
    print(f"\n{bcolors.OKBLUE} Executando Port Knocking...{bcolors.ENDC}")
    
    sucesso = knocker.execute_knock(target_ip, sequence)
    
    if sucesso:
        print(f"\n{bcolors.OKGREEN} Port Knocking realizado com sucesso!{bcolors.ENDC}")
        print(f"{bcolors.BOLD} Próximos passos:{bcolors.ENDC}")
        print(f"   1. No servidor {target_ip}, configure o firewall")
        print(f"   2. Teste a conexão SSH: ssh usuario@{target_ip}")
        
        registarLogs("sucesso", user[1], "port_knocking", 
                    f"Knocking para {target_ip} - sequência: {knocker.sequence}")
    else:
        print(f"\n{bcolors.FAIL} Port Knocking falhou!{bcolors.ENDC}")
        registarLogs("erro", user[1], "port_knocking", 
                    f"Falha no knocking para {target_ip}")

def configurar_firewall_knocking(user, knocker):
    print("\n" + "="*60)
    print("  CONFIGURAÇÃO DE FIREWALL")
    print("="*60)
    print(f"{bcolors.WARNING}ATENÇÃO: Esta operação requer privilégios de root/sudo{bcolors.ENDC}")
    
    confirmar = input(f"\n{bcolors.BOLD} Confirmar configuração? (s/N): {bcolors.ENDC}").lower().strip()
    
    if confirmar != "s":
        print(f"{bcolors.OKBLUE} Operação cancelada!{bcolors.ENDC}")
        return
    
    print(f"\n{bcolors.OKBLUE}  Configurando firewall...{bcolors.ENDC}")
    
    if knocker.configure_firewall():
        print(f"\n{bcolors.OKGREEN} Firewall configurado com sucesso!{bcolors.ENDC}")
        registarLogs("sucesso", user[1], "firewall_config", "Configuração iptables para port knocking")
    else:
        print(f"\n{bcolors.FAIL} Erro ao configurar firewall{bcolors.ENDC}")

def testar_ssh(user, knocker):
    print("\n" + "="*50)
    print(" TESTAR CONEXÃO SSH")
    print("="*50)
    
    target_ip = input("IP do servidor: ").strip()
    username = input("Utilizador SSH [kali]: ").strip() or "kali"
    
    if not target_ip:
        print(f"{bcolors.FAIL} IP é obrigatório!{bcolors.ENDC}")
        return
    
    print(f"\n{bcolors.OKBLUE} Testando conexão SSH para {username}@{target_ip}...{bcolors.ENDC}")

    
    if knocker.test_ssh_connection(target_ip, username):
        print(f"\n{bcolors.OKGREEN} Conexão SSH disponível!{bcolors.ENDC}")
        registarLogs("sucesso", user[1], "ssh_test", 
                    f"Conexão SSH OK para {username}@{target_ip}")
    else:
        print(f"\n{bcolors.FAIL} Conexão SSH não disponível{bcolors.ENDC}")

def definir_sequencia(knocker):
    print("\n" + "="*50)
    print(" DEFINIR NOVA SEQUÊNCIA")
    print("="*50)
    
    print(f"Sequência atual: {knocker.sequence}")
    
    nova_seq = input("\nNova sequência (ex: 1000,2000,3000): ").strip()
    
    if not nova_seq:
        print(f"{bcolors.OKBLUE}  Sequência mantida{bcolors.ENDC}")
        return
    
    try:
        sequencia = [int(p.strip()) for p in nova_seq.split(",")]
        
        if knocker.set_sequence(sequencia):
            print(f"\n{bcolors.OKGREEN} Sequência alterada para: {knocker.sequence}{bcolors.ENDC}")
        else:
            print(f"\n{bcolors.FAIL} Erro ao definir sequência{bcolors.ENDC}")
            
    except ValueError:
        print(f"{bcolors.FAIL} Formato inválido! Use números separados por vírgula.{bcolors.ENDC}")
# ========== FIM FUNÇÕES PORT KNOCKING ==========

def password_manager_menu(user):
    """
    Menu do Password Manager com 2FA
    NÃO usa try/except para não esconder erros
    """
    from password_manager.manager import password_manager_menu as pm_menu

    pm_menu(user)


def menuPrincipal(user):


    while True:
        clearScreen()   

        tipoUser = user[4]
        sufx = "(admin)" if tipoUser == 'admin' else ""

        print('\n=====================================================')
        print("\nUtilizador Logado: " + bcolors.BOLD + user[1] + sufx + bcolors.ENDC)
        print("\n--------- << M E N U  P R I N C I P A L >> ----------\n")

        if tipoUser == 'admin':
            print("[1] PORT SCANNER")
            print("[2] ANALISE LOGS SERVIÇOS [HTTP/SSH]")
            print("[3] ANALISE LOGS [auth.log]")
            print("[4] LIGAÇÕES")
            print("[5] BACKUP")
            print("[6] CHAT [INICIAR O SERVIDOR]")
            print("[7] UDP FLOOD ATTACK")
            print("[8] SYN FLOOD ATTACK")
            print("[9] PORT KNOCKING CLIENT")
            print("[10] PASSWORD MANAGER (2FA)")
        else:
            print("[C] CHAT")

        print("[S] SAIR")

        op = input(f"\n{bcolors.BOLD}>>> {bcolors.ENDC}").strip().lower()

        # --------- OPÇÕES ADMIN ---------
        if op == '1' and tipoUser == 'admin':
            portScanner(user)

        elif op == '2' and tipoUser == 'admin':
            analiseLogServicos(user)

        elif op == '3' and tipoUser == 'admin':
            analiseLogsAuth(user)

        elif op == '4' and tipoUser == 'admin':
            ligacoes(user)

        elif op == '5' and tipoUser == 'admin':
            backup(user)

        elif op == '6' and tipoUser == 'admin':
            servidor.initServidor()
            input("\nServidor iniciado. Pressione Enter para continuar...")

        elif op == '7' and tipoUser == 'admin':
            udp_flood_attack(user)
            input("\nPressione Enter para voltar ao menu principal...")

        elif op == '8' and tipoUser == 'admin':
            syn_flood_attack(user)
            input("\nPressione Enter para voltar ao menu principal...")

        elif op == '9' and tipoUser == 'admin':
            menu_port_knocking(user)

        elif op == '10' and tipoUser == 'admin':
            password_manager_menu(user)

        # --------- CLIENTE ---------
        elif op == 'c' and tipoUser != 'admin':
            submenuChat(user)

        # --------- SAIR ---------
        elif op == 's':
            logout(user[1])

        # --------- OPÇÃO INVÁLIDA ---------
        else:
            print(f"\n{bcolors.FAIL} Opção inválida!{bcolors.ENDC}")
            input("Pressione Enter para continuar...")

def ligacoes(user):
    print("\n------------------ << LIGAÇÕES >> ------------------")   
    dados = [] 
    resultados = os.popen('netstat -at -au')
    i=0
    for res in resultados.readlines():
        if i > 0:
            print(bcolors.BOLD+res+bcolors.ENDC)
            dados.append(res)
        i+=1
    registarLogs("sucesso",user[1],"list","listagem de ligações")    
    op = input('\nGerar relatorio PDF [y/n]:')
    if op == 'y':
        print('Processando, aguarde por favor...')
        sleep(1)
        gerarRelatorioLigacaoPDF("ligacoes","Ligações",dados)
        registarLogs("sucesso",user[1],"relatorio","relatorio ligações")
        print(f"{bcolors.OKGREEN}Relatorio gerado com sucesso{bcolors.ENDC} \n")    
    voltarMenuOuLogout(user)

def voltarMenuOuLogout(user):
    op = input("\nDeseja voltar ao menu principal? (s/n): ").lower()
    if op == 's':
        menuPrincipal(user)
    else:
        logout(user[1])


def gerarRelatorioLigacaoPDF(nomeFicheiro, titulo, dados):
   
    pass

if __name__ == "__main__":
    main()
