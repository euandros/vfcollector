#!/bin/bash

# Nome: Vansor Forensic Collector
# Descrição: Script de automação para coleta, validação e análise de dados de servidores Linux.
# As evidências coletadas são salvas de maneira mais segura e tornam-se automaticamente imutáveis.
# Autor: Evandro Santos
# Contato: evandro.santos@tutanota.com
# Data: Domingo, 08 de setembro de 2024, São Paulo.
# Versão: 1.0

COLETA=""

# Função para criar a pasta de evidências e aplicar imutabilidade nos arquivos
criar_pasta_evidencias() {
    echo "Criando pasta de evidências $COLETA..."
    mkdir "$COLETA"
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

verificar_acessos_suspeitos() {
    echo "Verificando acessos sudo não autorizados..."
    grep -i 'sudo:.*authentication failure' /var/log/auth.log > "./$COLETA/falhas_sudo.txt"
    tornar_arquivos_imutaveis
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
    echo "7. Verificar Processos Suspeitos"
    echo "8. Verificar Módulos do Kernel"
    echo "9. Verificar Portas Abertas"
    echo "10. Verificar Binários Modificados"
    echo "11. Verificar Acessos Sudo Suspeitos"
    echo "12. Verificar Arquivos Ocultos"
    echo "13. Gerar Hashes"
    echo "14. Compactar e Gerar Hash de Evidências"
    echo "15. Finalizar"
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
        7) verificar_processos_suspeitos;;
        8) verificar_modulos_kernel;;
        9) verificar_portas_abertas;;
        10) verificar_binarios_modificados;;
        11) verificar_acessos_suspeitos;;
        12) verificar_arquivos_ocultos;;
        13) gerar_hashes;;
        14) compactar_evidencias;;
        15) exit;;
        *) echo "Opção inválida!";;
    esac
done
