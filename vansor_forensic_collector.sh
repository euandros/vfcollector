#!/bin/bash

# Nome: Vansor Forensic Collector
# Descrição: Script de automação para coleta, validação e análise de dados de servidores Linux.
# As evidências coletadas são salvas de maneira mais segura e tornam-se automaticamente imutáveis.
# Autor: Evandro Santos
# Contato: evandro.santos@tutanota.com
# Data: Domingo, 08 de setembro de 2024, São Paulo.
# Versão: 1.2
# Detalhe da Atualização: Alteração da função para criar pasta, adição das funções para coleta dos dados: logs do audit,
#                         logs do journal, usuarios e grupos, arquivo shadow, tabela arp, resolv.conf, pacotes RPM ou DPKG.
# Agradecimentos: Obrigado @carlossilva9867 @hectorvido e @waldirio pelas contribuições de melhoria.

# Função para criar a pasta de evidências e aplicar imutabilidade nos arquivos
criar_pasta_evidencias() {
    local hostname=$(hostname)
    local data=$(date +"%Y%m%d_%H%M%S")
    COLETA="${hostname}_${data}"

    echo "Criando pasta de evidências $COLETA..."
    mkdir -p "$COLETA"
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

# Função para coletar informações de rede
coletar_informacoes_rede() {
    echo "Coletando informações de rede..."
    ip a > ./$COLETA/ifconfig.txt
    tornar_arquivos_imutaveis
}

# Função para coletar logs do audit
coletar_logs_audit() {
    echo "Coletando logs do audit..."
    ausearch -m all > ./$COLETA/logs_audit.txt
    tornar_arquivos_imutaveis
}

# Função para coletar data e hora
coletar_data_hora() {
    echo "Coletando data e hora..."
    date > ./$COLETA/data_hora.txt
    tornar_arquivos_imutaveis
}

# Função para coletar histórico de comandos
coletar_historico_comandos() {
    echo "Coletando histórico de comandos..."
    history > "./$COLETA/historico.txt"
    tornar_arquivos_imutaveis
}

# Função para coletar usuários logados
coletar_usuarios_logados() {
    echo "Coletando usuários logados..."
    w > ./$COLETA/usuarios_logados.txt
    tornar_arquivos_imutaveis
}

# Função para coletar dump da memória
coletar_dump_memoria() {
    echo "Coletando dump de memória via /proc/kcore..."
    dd if=/proc/kcore of=./$COLETA/mem_dump.lime bs=1M
    tornar_arquivos_imutaveis
}

# Função para coletar processos suspeitos
verificar_processos_suspeitos() {
    echo "Verificando processos suspeitos..."
    ps aux --sort=-%mem | head -n 10 > "./$COLETA/processos_suspeitos.txt"
    tornar_arquivos_imutaveis
}

# Função para coletar módulos do kernel
verificar_modulos_kernel() {
    echo "Verificando módulos do kernel..."
    lsmod > "./$COLETA/modulos_kernel.txt"
    tornar_arquivos_imutaveis
}

# Função para coletar portas abertas
verificar_portas_abertas() {
    echo "Coletando informações de portas abertas..."
    ss -tuln > "./$COLETA/portas_abertas.txt"
    tornar_arquivos_imutaveis
}

# Função para coletar binários modificados
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

# Função para coletar acessos suspeitos
verificar_acessos_suspeitos() {
    echo "Verificando acessos sudo não autorizados..."
    grep -i 'sudo:.*authentication failure' /var/log/auth.log > "./$COLETA/falhas_sudo.txt"
    tornar_arquivos_imutaveis
}

# Função para coletar arquivos ocultos
verificar_arquivos_ocultos() {
    echo "Verificando arquivos ocultos..."
    find / -name ".*" -exec ls -l {} \; > "./$COLETA/arquivos_ocultos.txt"
    tornar_arquivos_imutaveis
}

# Função para coletar logs do journal
coletar_logs_journal() {
    echo "Coletando logs do journal..."
    journalctl > ./$COLETA/logs_journal.txt
    tornar_arquivos_imutaveis
}

# Função para coletar lista de usuários e grupos
coletar_usuarios_grupos() {
    echo "Coletando usuários e grupos..."
    cat /etc/passwd > ./$COLETA/usuarios.txt
    cat /etc/group > ./$COLETA/grupos.txt
    tornar_arquivos_imutaveis
}

# Função para coletar o arquivo shadow
coletar_shadow() {
    echo "Coletando arquivo shadow..."
    cat /etc/shadow > ./$COLETA/shadow.txt
    tornar_arquivos_imutaveis
}

# Função para coletar a tabela ARP
coletar_tabela_arp() {
    echo "Coletando tabela ARP..."
    arp -a > ./$COLETA/tabela_arp.txt
    tornar_arquivos_imutaveis
}

# Função para coletar o resolv.conf
coletar_resolv_conf() {
    echo "Coletando resolv.conf..."
    cat /etc/resolv.conf > ./$COLETA/resolv.conf.txt
    tornar_arquivos_imutaveis
}

# Função para coletar pacotes instalados
coletar_pacotes_instalados() {
    echo "Coletando pacotes instalados..."
    if command -v dpkg &> /dev/null; then
        dpkg -l > ./$COLETA/pacotes_instalados.txt
    elif command -v rpm &> /dev/null; then
        rpm -qa > ./$COLETA/pacotes_instalados.txt
    else
        echo "Nenhum gerenciador de pacotes compatível encontrado." > ./$COLETA/pacotes_instalados.txt
    fi
    tornar_arquivos_imutaveis
}

# Função para gerar hashes dos arquivos gerados
gerar_hashes() {
    echo "Gerando hashes dos arquivos coletados..."
    sha256sum ./$COLETA/*.txt > ./$COLETA/hashes.txt
    tornar_arquivos_imutaveis
}

# Função para compactar as evidências e gerar hash
compactar_evidencias() {
    echo "Compactando evidências..."
    tar -czf ./$COLETA/evidencias.tar.gz -C $COLETA .
    sha256sum ./$COLETA/evidencias.tar.gz > ./$COLETA/evidencias.sha256
}

# Função para exibir o nome do script em ASCII art
exibir_nome_script() {
    echo "========================================"
    echo "=               VANSOR                 ="
    echo "=         FORENSIC COLLECTOR           ="
    echo "=                v1.2                  ="
    echo "=                                      ="
    echo "=         Vansor @ 2023-2024           ="
    echo "========================================"
    }

# Função para coletar tudo
coletar_tudo() {
    criar_pasta_evidencias
    coletar_informacoes_gerais
    coletar_informacoes_rede
    coletar_logs_audit
    coletar_data_hora
    coletar_historico_comandos
    coletar_usuarios_logados
    coletar_dump_memoria
    verificar_processos_suspeitos
    verificar_modulos_kernel
    verificar_portas_abertas
    verificar_binarios_modificados
    verificar_acessos_suspeitos
    verificar_arquivos_ocultos
    coletar_logs_journal
    coletar_usuarios_grupos
    coletar_shadow
    coletar_tabela_arp
    coletar_resolv_conf
    coletar_pacotes_instalados
    gerar_hashes
    compactar_evidencias
}

# Menu principal
while true; do
    clear
    exibir_nome_script
    echo ""
    echo "Data e Hora Atual: $(date)"
    echo ""
    echo "Selecione uma opção:"
    echo "0. Criar a pasta de coleta"
    echo "1. Coletar evidências"
    echo "2. Coletar informações gerais"
    echo "3. Coletar informações de rede"
    echo "4. Coletar logs do audit"
    echo "5. Coletar data e hora"
    echo "6. Coletar histórico de comandos"
    echo "7. Coletar usuários logados"
    echo "8. Coletar dump da memória"
    echo "9. Verificar processos suspeitos"
    echo "10. Verificar módulos do kernel"
    echo "11. Verificar portas abertas"
    echo "12. Verificar binários modificados"
    echo "13. Verificar acessos suspeitos"
    echo "14. Verificar arquivos ocultos"
    echo "15. Coletar logs do journal"
    echo "16. Coletar usuários e grupos"
    echo "17. Coletar arquivo shadow"
    echo "18. Coletar tabela ARP"
    echo "19. Coletar resolv.conf"
    echo "20. Coletar pacotes instalados"
    echo "21. Gerar hashes dos arquivos coletados"
    echo "22. Compactar evidências e gerar hash"
    echo "23. Sair"
    echo ""
    read -p "Digite sua escolha [0-23]: " escolha

    case $escolha in
        0) criar_pasta_evidencias ;;
        1) coletar_tudo ;;
        2) coletar_informacoes_gerais ;;
        3) coletar_informacoes_rede ;;
        4) coletar_logs_audit ;;
        5) coletar_data_hora ;;
        6) coletar_historico_comandos ;;
        7) coletar_usuarios_logados ;;
        8) coletar_dump_memoria ;;
        9) verificar_processos_suspeitos ;;
        10) verificar_modulos_kernel ;;
        11) verificar_portas_abertas ;;
        12) verificar_binarios_modificados ;;
        13) verificar_acessos_suspeitos ;;
        14) verificar_arquivos_ocultos ;;
        15) coletar_logs_journal ;;
        16) coletar_usuarios_grupos ;;
        17) coletar_shadow ;;
        18) coletar_tabela_arp ;;
        19) coletar_resolv_conf ;;
        20) coletar_pacotes_instalados ;;
        21) gerar_hashes ;;
        22) compactar_evidencias ;;
        23) echo "Saindo..."; exit ;;
        *) echo "Opção inválida!" ;;
    esac
done
