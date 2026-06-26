#!/usr/bin/env python3
# dns_tool_linkedin.py
# Versao simplificada e didatica de consulta DNS em Python
# Uso: python dns_tool_linkedin.py

"""
O que e DNS?
DNS (Domain Name System) traduz nomes de dominio em IPs.
Um dominio pode ter varios registros: A (IPv4), AAAA (IPv6),
MX (email), NS (servidores DNS), TXT (verificacao) e CNAME (alias).

Este script consulta esses registros e tambem tenta descobrir
subdominios por brute force com wordlist interna.

Instalacao: pip install dnspython
"""

# ---------------------------------------------------------------------------
# PASSO 0: IMPORTACAO DE MODULOS
# ---------------------------------------------------------------------------

import sys  # Para funcoes do sistema (exit, argv, etc.)

# Valida se a biblioteca dnspython esta instalada antes de prosseguir
# Se nao estiver, exibe instrucoes de instalacao e encerra o script
try:
    import dns.resolver  # Modulo principal para consultas DNS
except ImportError:
    print("[!] Biblioteca 'dnspython' nao encontrada!")
    print("[?] Instale com: pip install dnspython")
    sys.exit(1)  # Encerra com codigo de erro


# ---------------------------------------------------------------------------
# PASSO 1: DEFINICAO DE DADOS
# ---------------------------------------------------------------------------

# WORDLIST: subdominios comuns para brute force
# O brute force testa cada nome + dominio alvo.
# Se retornar IP = aquele subdominio existe.
# Em ambientes reais, wordlists podem ter milhares de entradas.
WORDLIST = [
    "www", "mail", "smtp", "imap", "webmail",
    "ftp", "ssh", "mysql", "admin", "blog",
    "api", "dev", "test", "staging", "beta",
    "ns1", "ns2", "ns3", "ns4",
    "intranet", "portal", "server", "backup",
    "cpanel", "whm", "phpmyadmin", "status",
]

# TIPOS DE REGISTRO DNS que serao consultados:
# A     -> Endereco IPv4 do dominio (ex: 192.168.1.1)
# AAAA  -> Endereco IPv6 do dominio
# MX    -> Servidores de email (Mail Exchange)
# NS    -> Servidores DNS autoritativos
# TXT   -> Registros de texto (SPF, verificacao, etc.)
# CNAME -> Alias/apontamento para outro dominio
TIPOS = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]


# ---------------------------------------------------------------------------
# PASSO 2: FUNCOES DE CONSULTA DNS
# ---------------------------------------------------------------------------

def consultar_registros(dominio, tipos):
    """Consulta os registros DNS de um dominio.

    Para cada tipo de registro (A, MX, NS, etc.), tenta resolver
    usando a biblioteca dnspython. Se o registro existir, retorna
    os valores encontrados. Se nao existir, ignora silenciosamente.

    Funcao importante para:
    - Descobrir o IP de um site
    - Saber onde o email esta hospedado
    - Identificar servidores DNS
    - Verificar configuracao SPF/DKIM (registros TXT)
    """
    resultados = {}  # Dicionario para armazenar todos os registros

    for tipo in tipos:
        # --- PROCESSO DE CONSULTA DNS ---
        # 1. Envia requisicao ao servidor DNS autoritativo
        # 2. O servidor responde com os registros do tipo solicitado
        # 3. Se nao tiver o registro, retorna erro NoAnswer
        # 4. Se o dominio nao existir, retorna erro NXDOMAIN
        try:
            # dns.resolver.resolve() faz a consulta ao servidor DNS
            # Exemplo: resolve("google.com", "A") retorna IPs do Google
            respostas = dns.resolver.resolve(dominio, tipo)

            # Converte cada resposta para string e armazena na lista
            # str(r) converte objetos DNS em texto legivel
            resultados[tipo] = [str(r) for r in respostas]

        except dns.resolver.NoAnswer:
            # Dominio existe, mas NAO tem esse tipo de registro
            # Ex: dominio sem registro MX nao recebe email
            resultados[tipo] = []

        except dns.resolver.NXDOMAIN:
            # O dominio NAO existe nos servidores DNS
            # Pode ter sido deletado ou nunca registrado
            print(f"\n  Dominio '{dominio}' nao encontrado!")
            return None  # Retorna None para indicar erro

        except Exception as e:
            # Qualquer outro erro (timeout, sem conexao, etc.)
            resultados[tipo] = [f"Erro: {e}"]

    return resultados  # Retorna dicionario com todos os registros


def exibir_registros(dominio, resultados):
    """Exibe os registros DNS formatados na tela.

    Mostra os resultados organizados por tipo de registro.
    Registros vazios nao sao exibidos para manter a saida limpa.
    """
    print("\n" + "=" * 50)
    print(f"  DNS: {dominio}")
    print("=" * 50)

    for tipo, valores in resultados.items():
        if valores:  # So exibe se houver valores encontrados
            print(f"\n  [{tipo}]")  # Tipo do registro
            for v in valores:
                print(f"    {v}")  # Valor do registro


# ---------------------------------------------------------------------------
# PASSO 3: FUNCAO DE BRUTE FORCE
# ---------------------------------------------------------------------------

def brute_force_subdominios(dominio, wordlist):
    """Tenta descobrir subdominios por brute force.

    O brute force consiste em testar combinacoes de subdominios
    comuns (www, mail, ftp, admin, etc.) e verificar se existem.

    Para cada subdominio da wordlist:
    1. Monta o FQDN: "sub.dominio.com.br"
    2. Tenta resolver o registro A (IPv4)
    3. Se encontrar IP = subdominio existe!
    4. Se nao encontrar, ignora e continua

    Em ferramentas profissionais, isso e feito com wordlists
    maiores e threads paralelas para ser mais rapido.
    """
    print("\n" + "-" * 50)
    print("  Brute force de subdominios:")
    print("-" * 50)

    encontrados = []  # Lista para armazenar subdominios descobertos

    # --- PROCESSO DE BRUTE FORCE ---
    # Para cada nome na wordlist, testa se "nome.dominio.com.br" existe
    for sub in wordlist:
        # Monta o FQDN (Fully Qualified Domain Name)
        # Exemplo: "www" + "crn10.org.br" = "www.crn10.org.br"
        fqdn = f"{sub}.{dominio}"

        try:
            # Tenta resolver o registro A (IPv4) deste subdominio
            ip = dns.resolver.resolve(fqdn, "A")

            # Se chegou aqui, o subdominio EXISTE!
            ips = ", ".join(str(r) for r in ip)
            print(f"  [+] {fqdn} -> {ips}")
            encontrados.append(f"{fqdn} -> {ips}")

        except Exception:
            # Subdominio NAO existe ou erro de conexao
            # Nesse caso, apenas ignora e continua o loop
            pass

    return encontrados  # Retorna lista de subdominios encontrados


# ---------------------------------------------------------------------------
# PASSO 4: FUNCAO DE SALVAMENTO
# ---------------------------------------------------------------------------

def salvar_resultados(dominio, registros, subdominios):
    """Salva todos os resultados em arquivo .txt.

    Cria um arquivo com o nome do dominio e grava:
    1. Todos os registros DNS encontrados
    2. Todos os subdominios descobertos
    3. Data e hora da consulta

    Util para manter historico de auditorias e pentests.
    """
    from datetime import datetime  # Para data/hora no arquivo

    # Gera nome do arquivo: dns_exemplo_com_br.txt
    # Substitui pontos e barras por underscores
    nome_arquivo = f"dns_{dominio.replace('.', '_').replace('/', '_')}.txt"

    # Abre arquivo para escrita (cria se nao existir)
    with open(nome_arquivo, 'w', encoding='utf-8') as f:
        # Cabecalho do arquivo
        f.write(f"Consulta DNS: {dominio}\n")
        f.write(f"Data: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
        f.write("=" * 50 + "\n\n")

        # Grava registros DNS organizados por tipo
        f.write("REGISTROS DNS:\n\n")
        for tipo, valores in registros.items():
            if valores:
                f.write(f"[{tipo}]\n")
                for v in valores:
                    f.write(f"  {v}\n")
                f.write("\n")

        # Grava subdominios encontrados
        if subdominios:
            f.write("\nSUBDOMINIOS ENCONTRADOS:\n\n")
            for sub in subdominios:
                f.write(f"  {sub}\n")

    print(f"\n  Resultados salvos em: {nome_arquivo}")


# ---------------------------------------------------------------------------
# PASSO 5: FUNCAO PRINCIPAL
# ---------------------------------------------------------------------------

def main():
    """Funcao principal que coordena todo o fluxo do script:

    1. Pede o dominio ao usuario
    2. Consulta todos os registros DNS
    3. Exibe os registros formatados
    4. Executa brute force de subdominios
    5. Salva tudo em arquivo .txt
    """
    # --- ENTRADA DO USUARIO ---
    dominio = input("Digite o dominio: ").strip()

    # Valida a entrada basica (deve ter pelo menos um ponto)
    if not dominio or '.' not in dominio:
        print("Formato invalido! Use: ex.com.br")
        return

    # --- PASSO A: Consulta registros DNS ---
    resultados = consultar_registros(dominio, TIPOS)
    if resultados is None:
        return  # Dominio nao encontrado, encerra

    # --- PASSO B: Exibe registros na tela ---
    exibir_registros(dominio, resultados)

    # --- PASSO C: Brute force de subdominios ---
    subdominios = brute_force_subdominios(dominio, WORDLIST)

    # --- PASSO D: Salva resultados em arquivo ---
    salvar_resultados(dominio, resultados, subdominios)

    # --- RESUMO FINAL ---
    total_subs = len(subdominios) if subdominios else 0
    print("\n" + "=" * 50)
    print(f"  Consulta concluida!")
    print(f"  Registros DNS: {len([k for k, v in resultados.items() if v])} tipos")
    print(f"  Subdominios: {total_subs} encontrados")
    print("=" * 50)


# ---------------------------------------------------------------------------
# INICIO DO SCRIPT
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    main()
