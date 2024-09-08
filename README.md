# Vansor Forensic Collector v1.0

## Descrição

O **Vansor Forensic Collector** é um script de automação desenvolvido para coleta, validação e análise de dados em servidores Linux. Destinado a operações de análise forense, o script coleta uma variedade de informações do sistema, realiza verificações e gera relatórios que são tornados imutáveis para garantir a integridade dos dados.

## Funcionalidades

- **Criação e Imutabilidade da Pasta de Evidências**
  - Cria uma pasta para armazenar evidências e torna todos os arquivos nessa pasta imutáveis usando `chattr +i`.

- **Coleta de Informações Gerais**
  - Coleta e salva informações como nome do computador, data de instalação, tempo de atividade, informações de hardware, data de lançamento do BIOS, informações da CPU e disco.

- **Coleta de Informações de Rede**
  - Registra informações de rede com `ip a`.

- **Coleta de Data e Hora**
  - Salva a data e a hora atuais em um arquivo.

- **Coleta de Histórico de Comandos**
  - Captura e salva o histórico de comandos do shell.

- **Coleta de Usuários Logados**
  - Registra a lista de usuários logados.

- **Coleta de Dump de Memória**
  - Gera um dump da memória usando `/proc/kcore`.

- **Verificações e Análises**
  - **Processos Suspeitos**: Identifica processos com alto uso de memória.
  - **Módulos do Kernel**: Lista os módulos do kernel carregados.
  - **Portas Abertas**: Captura informações sobre portas abertas.
  - **Binários Modificados**: Verifica binários modificados usando `debsums` ou `rpm`.
  - **Acessos Sudo Suspeitos**: Verifica falhas de autenticação no `auth.log`.
  - **Arquivos Ocultos**: Identifica arquivos ocultos no sistema.

- **Geração de Hashes e Compactação**
  - Gera hashes SHA-256 para os arquivos coletados e compacta todos os arquivos em um `.tar.gz`, com um hash para o arquivo compactado.

## Uso

1. **Clone o repositório:**
   ```bash
   git clone https://github.com/euandros/vfcollector.git
   cd vansor-forensic-collector
   ```
   
2. **Dê permissão de execução ao script:**
   ```bash
   chmod +x vansor_forensic_collector.sh
   ```
   
3. **Execute o script:**
   ```bash
   ./vansor_forensic_collector.sh
   ```
   
3. **Execute o script:**
   ```bash
   ./vansor_forensic_collector.sh
   
   Siga as instruções do menu para selecionar as operações desejadas.
   ```

3. **#xemplo da saída:**

![image](https://github.com/user-attachments/assets/c6d3d156-a9fc-42d3-ab03-5052bb22bf0c)


## Observações

* **Imutabilidade dos Arquivos**: Todos os arquivos gerados são tornados imutáveis para garantir a integridade dos dados.
* **Dump de Memória**: O script utiliza o /proc/kcore para gerar o dump da memória, uma abordagem que evita a instalação de ferramentas adicionais e minimiza o impacto no sistema.

## Contribuições
Sinta-se à vontade para contribuir com melhorias ou sugestões enviando pull requests ou abrindo issues no repositório.

## Licença
Este projeto está licenciado sob a MIT License.
