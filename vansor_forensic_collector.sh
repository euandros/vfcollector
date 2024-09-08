#!/bin/bash

# Nome: Vansor Forensic Collector
# Descrição: Script de automação para coleta, validação e análise de dados de servidores Linux.
# As evidências coletadas são salvas de maneira mais segura e tornam-se automaticamente imutáveis.
# Autor: Evandro Santos
# Contato: evandro.santos@tutanota.com
# Data: Domingo, 08 de setembro de 2024, São Paulo.
# Versão: 1.2

COLETA=""

# Função para criar a pasta de evidências e aplicar imutabilidade nos arquivos
criar_pasta_evidencias() {
    echo "Criando pasta de evidências $COLETA..."
    if [ -d $COLETA ]; then
      echo "Pasta ja criada"
    else
      echo "Criando pasta de evidências $COLETA..."
      mkdir -v "$COLETA"
    fi
}

# Função para tornar arquivos imutáveis automaticamente
tornar_arquivos_imutaveis() {
    echo "Tornando arquivos imutáveis..."
    chattr +i ./$COLETA/*.txt
}

# Função para coletar informações gerais e aplicar imutabilidade
coletar_informacoes_gerais() {
    echo "Coletando informações gerais do computador..."
    NOMECOMPUTADOR=$(cat /etc/hostname)
    echo "Nome do Computador: $NOMECOMPUTADOR" > ./$COLETA/informacoes-gerais.txt

    echo "Coletando data de instalação..."
    DISCO=$(df -h | grep '/$' | cut -d' ' -f1)
    data_instalacao=$(tune2fs -l $DISCO | grep created)
    echo "$data_instalacao" >> ./$COLETA/informacoes-gerais.txt

    echo "Coletando tempo de atividade do sistema..."
    ligado=$(uptime)
    echo "Tempo de Atividade: $ligado" >> ./$COLETA/informacoes-gerais.txt

    echo "Coletando informações de hardware..."
    dmidecode -t 1 >> ./$COLETA/informacoes-gerais.txt

    echo "Coletando data de lançamento do BIOS..."
    data_bios=$(dmidecode -s bios-release-date)
    echo -e "\tData de Lançamento do BIOS: $data_bios" >> ./$COLETA/informacoes-gerais.txt

    echo "Coletando informações da CPU..."
    lscpu >> ./$COLETA/informacoes-gerais.txt

    echo "Coletando informações do disco..."
    df -hT >> ./$COLETA/informacoes-gerais.txt

    # Tornar os arquivos coletados imutáveis
    tornar_arquivos_imutaveis
}

coletar_informacoes_rede() {
    echo "Coletando informações de rede..."
    ip a > ./$COLETA/ifconfig.txt

    echo "Roteamento"
    route -n > ./$COLETA/route.txt

    echo "Tabela ARP"
    arp -a > ./$COLETA/route.txt

    echo "Servidor DNS"
    cat /etc/resolv.conf  > ./$COLETA/resolv.txt
    tornar_arquivos_imutaveis
}

coletar_data_hora() {
    echo "Coletando data e hora..."
    date > ./$COLETA/data_hora.txt
    tornar_arquivos_imutaveis
}

coletar_historico_comandos() {
    echo "Coletando histórico de comandos..."
    history > "./$COLETA/historico.txt"
    tornar_arquivos_imutaveis
}

coletar_usuarios_logados() {
    echo "Coletando usuários logados..."
    w > ./$COLETA/usuarios_logados.txt
    tornar_arquivos_imutaveis
}

coletar_dump_memoria() {
    echo "Coletando dump de memória via /proc/kcore..."
    dd if=/proc/kcore of=./$COLETA/mem_dump.lime bs=1M
    tornar_arquivos_imutaveis
}
verificar_processos_suspeitos() {
    echo "Verificando processos suspeitos..."
    ps aux --sort=-%mem | head -n 10 > "./$COLETA/processos_suspeitos.txt"
    tornar_arquivos_imutaveis
}

verificar_modulos_kernel() {
    echo "Verificando módulos do kernel..."
    lsmod > "./$COLETA/modulos_kernel.txt"
    tornar_arquivos_imutaveis
}

verificar_portas_abertas() {
    echo "Coletando informações de portas abertas..."
    ss -tuln > "./$COLETA/portas_abertas.txt"
    tornar_arquivos_imutaveis
}

verificar_binarios_modificados() {
    echo "Verificando binários modificados..."
    if command -v debsums &> /dev/null; then
        debsums -c > "./$COLETA/binarios_modificados.txt"
    elif command -v rpm &> /dev/null; then
        rpm -Va > "./$COLETA/binarios_modificados.txt"
    else
        echo "Sistema não possui debsums ou rpm para verificação de binários." > "./$COLETA/binarios_modificados.txt"
    fi
    tornar_arquivos_imutaveis
}

verificar_usuarios_e_grupos() {
    echo "Verificando usuarios no sistema"
    echo "Copiando arquivo passwd"
    cat /etc/passwd >  "./$COLETA/passwd.txt"

    echo "Copiando arquivo /etc/group"
    cat /etc/group > "./$COLETA/group.txt"

    echo "Copiando arquivo sudoers" 
    cat /etc/sudoers | grep -Ev '[:blank]*#|^[:blank]*$' | awk '{print $1,$2}' >  "./$COLETA/sudoers.txt"

    echo "Verificando usuarios bloqueados"
    cat /etc/shadow | grep -i ! | cut -d: -f1 >  "./$COLETA/usuarios_bloqueados.txt"
    grep -i 'sudo:.*authentication failure' /var/log/auth.log > "./$COLETA/falhas_sudo.txt"

    tornar_arquivos_imutaveis
}

verificar_acessos_suspeitos() {
    echo "Verificando acessos sudo não autorizados..."
    grep -i 'sudo:.*authentication failure' /var/log/auth.log > "./$COLETA/falhas_sudo.txt"
    # ultimos logons
    
    echo "Verificando ultimos logins"
    lastlog | grep -v "**Never logged in**" > "./$COLETA/lastlog.txt"

    tornar_arquivos_imutaveis
}

verificar_pacotes_instalados(){
    # Debian (DEB)
    if command -v dpkg &> /dev/null; then
        echo "dpkg está instalado no sistema."
        dpkg -l "./$COLETA/pacotes.txt"
    # RPM
    elif command -v rpm &> /dev/null; then
        echo "rpm está instalado no sistema."
        rpm -qa "./$COLETA/pacotes.txt"
    else
        echo "Nenhum dos gerenciadores de pacotes (dpkg ou rpm) está instalado."
    fi
}

coletar_logs_e_registros() {
    # Criando diretorio especifico para logs de auditoria do linux
    mkdir -p $COLETA/logs/
    # Lista de arquivos ou diretórios para copiar
    itens=("apt" "audit" "auth.log" "btmp" "cron.log" "daemon.log" "debug" "dpkg.log" "error.1" "faillog" "journal" "kern.log" "lastlog" "mail.info" "mail.log" "mail.warn" "messages" "syslog" "sysstat" "vzdump" "wtmp")
    # Loop para copiar cada item
    for item in "${itens[@]}"; do
        # Verifica se o item existe no diretório de origem
        if [ -e "/var/log/$item" ]; then
            echo "Copiando $item para o destino..."
            cp -r "/var/log/$item" "$COLETA/logs"
        else
            echo "$item não encontrado em /var/log"
        fi
    done
}

verificar_arquivos_ocultos() {
    echo "Verificando arquivos ocultos..."
    find / -name ".*" -exec ls -l {} \; > "./$COLETA/arquivos_ocultos.txt"
    tornar_arquivos_imutaveis
}

gerar_hashes() {
    echo "Gerando hashes dos arquivos coletados..."
    sha256sum ./$COLETA/*.txt > ./$COLETA/hashes.txt
    tornar_arquivos_imutaveis
}

compactar_evidencias() {
    echo "Compactando evidências..."
    tar -czf ./$COLETA/evidencias.tar.gz -C $COLETA .
    sha256sum ./$COLETA/evidencias.tar.gz > ./$COLETA/evidencias.sha256
}

# Função para coletar tudo
coletar_tudo() {
    coletar_informacoes_gerais
    coletar_informacoes_rede
    coletar_data_hora
    coletar_historico_comandos
    coletar_usuarios_logados
    coletar_dump_memoria
    coletar_logs_e_registros
    verificar_processos_suspeitos
    verificar_modulos_kernel
    verificar_usuarios_e_grupos
    verificar_portas_abertas
    verificar_binarios_modificados
    verificar_pacotes_instalados
    verificar_acessos_suspeitos
    verificar_arquivos_ocultos
    gerar_hashes
    compactar_evidencias
}

# Função para exibir o nome do script em ASCII art
exibir_nome_script() {
    echo "========================================="
    echo "=     __      __ ____ ______ ______     ="      
    echo "=     \ \    / / ____|  ___|/ ____|     ="
    echo "=      \ \  / / (___ | |__ | |          ="  
    echo "=       \ \/ / \___ \| |__|| |          ="  
    echo "=        \  /  ____) | |   | |____      ="  
    echo "=         \/  |_____/|_|    \_____|     ="
    echo "=                                       ="
    echo "=             Forensic Collector v1     ="
    echo "=                                       ="
    echo "=                                       ="
    echo "=          Vansor @ 2023-2024           ="
    echo "========================================="
    }

menu_selecao() {
    clear
    exibir_nome_script
    echo ""
    echo "Data e Hora Atual: $(date)"
    echo ""
    echo "Selecione a operação:"
    echo""
    echo "1. Coletar Informações Gerais"
    echo "2. Coletar Informações de Rede"
    echo "3. Coletar Data e Hora"
    echo "4. Coletar Histórico de Comandos"
    echo "5. Coletar Usuários Logados"
    echo "6. Coletar Dump de Memória"
    echo "7. Coleta de logs e registros"
    echo "8. Verificar Processos Suspeitos"
    echo "9. Verificar Módulos do Kernel"
    echo "10. Verificar Usuarios e grupos no sistema"
    echo "11. Verificar Portas Abertas"
    echo "12. Verificar Binários Modificados"
    echo "13. Verificar pacotes instalados"
    echo "14. Verificar Acessos Sudo Suspeitos"
    echo "15. Verificar Arquivos Ocultos"
    echo "16. Gerar Hashes"
    echo "17. Compactar e Gerar Hash de Evidências"
    echo "tudo. Coletar todos os logs"
    echo "0. Finalizar"
    echo ""
}

# Início do script

echo "Digite o nome para a pasta de evidências:"
read COLETA

while true; do
    menu_selecao
    read -p "Digite o número da operação desejada: " opcao

    case $opcao in
        1) criar_pasta_evidencias; coletar_informacoes_gerais;;
        2) coletar_informacoes_rede;;
        3) coletar_data_hora;;
        4) coletar_historico_comandos;;
        5) coletar_usuarios_logados;;
        6) coletar_dump_memoria;;
        6) coletar_dump_memoria;;
        7) coletar_logs_e_registros;;
        8) verificar_processos_suspeitos;;
        9) verificar_modulos_kernel;;
        10) verificar_usuarios_e_grupos;;
        11) verificar_portas_abertas;;
        12) verificar_binarios_modificados;;
        13) verificar_pacotes_instalados;;
        14) verificar_acessos_suspeitos;;
        15) verificar_arquivos_ocultos;;
        16) gerar_hashes;;
        17) compactar_evidencias;;
        0) exit;;
        tudo) coletar_tudo;;
        *) echo "Opção inválida!";;
    esac
done
